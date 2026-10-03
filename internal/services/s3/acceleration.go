package s3

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketAccelerateConfiguration(ctx context.Context, in *api.GetBucketAccelerateConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketAccelerateConfiguration", value(in.Bucket), "", "accelerate")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.accelerationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		response := &api.GetBucketAccelerateConfigurationOutput{}
		if bucket.AccelerationStatus != "" {
			response.Status = new(api.BucketAccelerateStatus(bucket.AccelerationStatus))
		}
		return out.prepare(c, response)
	})
	return out, wire
}

func (s *Service) putBucketAccelerateConfiguration(ctx context.Context, in *api.PutBucketAccelerateConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.transferCall(ctx, "PutBucketAccelerateConfiguration", value(in.Bucket), "")
	c.params["accelerate"] = ""
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.accelerationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		request, _ := awsapi.FromContext(tx.Context())
		c.additional["bytesTransferredIn"] = len(request.Body)
		status := value(in.AccelerateConfiguration.Status)
		if status == "" {
			return missingAccelerationStatus()
		}
		bucket.AccelerationStatus = status
		if err := tx.PutBucket(bucket); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketAccelerateConfigurationOutput{})
	})
	return out, wire
}

// Acceleration resolves location and authority before admitting its XML body.
// The same owner is used when generated binding or a transfer checksum rejects
// a request; rejected input is never dispatched as a command.
func (s *Service) accelerationBucket(reader Reader, c *apiCall, expected *api.AccountId) (BucketRecord, error) {
	bucket, err := s.configurationBucket(reader, c, expected)
	if err != nil {
		return bucket, err
	}
	host, _ := c.params["Host"].(string)
	if wire := admitS3Endpoint(host, bucket.Key.Partition, bucket.Region, bucket.Key.Name); wire != nil {
		return bucket, wire
	}
	action := "GetAccelerateConfiguration"
	if c.name == "PutBucketAccelerateConfiguration" {
		action = "PutAccelerateConfiguration"
	}
	if wire := s.authorize(reader.Context(), c, bucket, action, "", nil); wire != nil {
		return bucket, wire
	}
	if c.name == "PutBucketAccelerateConfiguration" && strings.Contains(bucket.Key.Name, ".") {
		return bucket, failure("InvalidRequest", "S3 Transfer Acceleration is not supported for buckets with periods (.) in their names", 400)
	}
	return bucket, nil
}

func missingAccelerationStatus() *awswire.Error {
	return failure("IllegalAccelerateConfigurationException", "The Accelerate element must be specified", 400)
}

func admitAcceleration(ctx context.Context, c *apiCall, bucket BucketRecord) *awswire.Error {
	// A copy's source is read internally, not through the destination's host.
	if c.copySource {
		return nil
	}
	host, _ := c.params["Host"].(string)
	host = s3EndpointHost(host)
	if !strings.HasSuffix(host, ".s3-accelerate.amazonaws.com") && !strings.HasSuffix(host, ".s3-accelerate.dualstack.amazonaws.com") {
		return nil
	}
	switch bucket.AccelerationStatus {
	case "":
		return failure("InvalidRequest", "S3 Transfer Acceleration is not configured on this bucket", 400)
	case "Suspended":
		return failure("InvalidRequest", "S3 Transfer Acceleration is disabled on this bucket", 400)
	}
	// Access-point admission already owns the alias's signing region.
	if c.accessPoint == nil {
		return admitS3SigningRegion(ctx, bucket.Region)
	}
	return nil
}
