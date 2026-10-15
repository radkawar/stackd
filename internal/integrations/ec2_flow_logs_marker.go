package integrations

import (
	"context"

	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

// Native admission creates a real zero-byte object before any flow traffic. Its
// key stops at the account partition, including for Hive/hour destinations.
// The retained calibration also observes marker reuse when another live flow
// in the same account/region already delivers to the bucket.
func (a *EC2FlowLogs) initializeS3(ctx context.Context, record ec2.FlowLogRecord) *awswire.Error {
	bucket, prefix, wire := flowLogBucket(record.Destination)
	if wire != nil {
		return wire
	}
	if a.Subscriptions == nil {
		return flowLogDeliveryError("Flow-log destination admission state is unavailable.")
	}
	alreadyAdmitted := false
	if err := a.Subscriptions.View(ctx, func(tx ec2.Reader) error {
		rows, err := tx.FlowLogs(record.Key.Scope)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.DestinationType != "s3" || row.Key == record.Key {
				continue
			}
			other, _, rejected := flowLogBucket(row.Destination)
			if rejected == nil && other == bucket {
				alreadyAdmitted = true
				break
			}
		}
		return nil
	}); err != nil {
		return serviceRoleFailure(err)
	}
	if alreadyAdmitted {
		return nil
	}
	if prefix != "" {
		prefix += "/"
	}
	prefix += "AWSLogs/"
	if record.HivePartitions {
		prefix += "aws-account-id="
	}
	prefix += record.Key.Scope.AccountID + "/"
	_, wire = a.S3.PutObject(flowLogS3Context(ctx, record.Key), &s3api.PutObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(prefix)), Body: []byte{}, ACL: new(s3api.ObjectCannedACL("bucket-owner-full-control")), ContentType: new(s3api.ContentType("application/octet-stream"))})
	return wire
}
