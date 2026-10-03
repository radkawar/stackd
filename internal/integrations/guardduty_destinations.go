package integrations

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/s3"
)

// GuardDutyDestinationS3 keeps destination existence, object bytes, encryption
// and resource policies in their authoritative S3/KMS owners.
type GuardDutyDestinationS3 interface {
	GetBucketLocation(context.Context, *api.GetBucketLocationInput) (*api.GetBucketLocationOutput, *awswire.Error)
	ListObjectsV2(context.Context, *api.ListObjectsV2Input) (*api.ListObjectsV2Output, *awswire.Error)
	HeadObject(context.Context, *api.HeadObjectInput) (*s3.ObjectResponse[api.HeadObjectOutput], *awswire.Error)
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
}

type GuardDutyDestinations struct{ S3 GuardDutyDestinationS3 }

var _ guardduty.PublishingDestinationSink = GuardDutyDestinations{}

func destinationS3Context(ctx context.Context, d guardduty.PublishingDestination) context.Context {
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	principal := guardduty.ServicePrincipal
	if awscatalog.CommercialRegionRequiresOptIn(d.Region) {
		principal = "guardduty." + d.Region + ".amazonaws.com"
	}
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: d.Partition, AccountID: d.AccountID, Region: d.Region,
		RequestID: uuid.NewString(), ParentEventID: parent,
		// Internal S3 delivery is trusted transport, not the originating HTTP
		// caller's connection or credentials. Preserve source detector identity.
		TransportKnown: true, SecureTransport: true,
		ServicePrincipal: awsctx.ServicePrincipal{Name: principal, SourceARN: "arn:" + d.Partition + ":guardduty:" + d.Region + ":" + d.AccountID + ":detector/" + d.DetectorID, Type: "AWSService"},
	})
}

func destinationS3Location(d guardduty.PublishingDestination) (string, string, error) {
	parsed, err := arn.Parse(d.DestinationARN)
	if err != nil || parsed.Service != "s3" || parsed.Partition != d.Partition || parsed.Region != "" || parsed.AccountID != "" {
		return "", "", destinationS3Failure("The request failed because the value specified for the destinationArn parameter is not valid.")
	}
	bucket, prefix, _ := strings.Cut(parsed.Resource, "/")
	if bucket == "" {
		return "", "", destinationS3Failure("The request failed because the value specified for the destinationArn parameter is not valid.")
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return bucket, prefix, nil
}

func destinationS3Failure(message string) error {
	return &awswire.Error{Code: "BadRequestException", Message: message, StatusCode: 400}
}

func destinationS3Rejection(err *awswire.Error) error {
	if err.Code == "NoSuchBucket" {
		return destinationS3Failure("The request failed because the resource specified in the destinationArn parameter does not exist.")
	}
	if err.StatusCode >= 500 {
		return err
	}
	return destinationS3Failure("The request failed because the GuardDuty service principal does not have permission to the KMS key or the resource specified by the destinationArn parameter. Refer to https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html")
}

func destinationPrefixRejection(err *awswire.Error) error {
	if err.StatusCode == 403 {
		return destinationS3Failure("The request failed because you do not have the required permissions for the s3:GetObject or s3:ListBucket actions.")
	}
	return err
}

func (a GuardDutyDestinations) Validate(ctx context.Context, d guardduty.PublishingDestination) error {
	if a.S3 == nil {
		return errors.New("GuardDuty S3 destination owner is unavailable")
	}
	bucket, prefix, err := destinationS3Location(d)
	if err != nil {
		return err
	}
	key, err := arn.Parse(d.KMSKeyARN)
	if err != nil || key.Service != "kms" || key.Partition != d.Partition || key.Region == "" || key.AccountID == "" || !strings.HasPrefix(key.Resource, "key/") || len(key.Resource) == len("key/") {
		return destinationS3Failure("The request failed because the value specified for the kmsKeyArn parameter is not valid.")
	}
	service := destinationS3Context(ctx, d)
	location, rejected := a.S3.GetBucketLocation(service, &api.GetBucketLocationInput{Bucket: new(api.BucketName(bucket))})
	if rejected != nil {
		return destinationS3Rejection(rejected)
	}
	region := stringValue(location.LocationConstraint)
	if region == "" {
		region = "us-east-1"
	}
	if key.Region != region {
		return destinationS3Failure("The request failed because the value specified for the kmsKeyArn parameter is not valid.")
	}
	if awscatalog.CommercialRegionRequiresOptIn(region) && region != d.Region {
		return destinationS3Failure("The destination bucket cannot be in a different opt-in Region.")
	}
	if prefix != "" {
		// The documented service policy permits GetBucketLocation and PutObject,
		// not listing or reading. Explicit-prefix discovery uses current caller
		// authority; the delivery itself never borrows that identity.
		// Native publishing_destinations_prefix_authority.json confirms caller
		// denial is a GuardDuty BadRequestException, not an S3 protocol error.
		metadata := awsctx.FromContext(ctx)
		metadata.Region = region
		caller := awsctx.WithMetadata(ctx, metadata)
		listed, rejected := a.S3.ListObjectsV2(caller, &api.ListObjectsV2Input{Bucket: new(api.BucketName(bucket)), Prefix: new(api.Prefix(prefix)), MaxKeys: new(api.MaxKeys(1))})
		if rejected != nil {
			return destinationPrefixRejection(rejected)
		}
		if len(listed.Contents) == 0 {
			return destinationS3Failure("The request failed because the resource folder specified in the destinationArn parameter does not exist.")
		}
		if _, rejected := a.S3.HeadObject(caller, &api.HeadObjectInput{Bucket: new(api.BucketName(bucket)), Key: listed.Contents[0].Key}); rejected != nil {
			return destinationPrefixRejection(rejected)
		}
	}
	// Native admission leaves this encrypted empty marker even when replaying
	// an existing client token. S3 owns both header conditions and GenerateDataKey.
	return a.put(service, d, bucket, prefix+"AWSLogs/", nil, false)
}

func (a GuardDutyDestinations) Export(ctx context.Context, d guardduty.PublishingDestination, key string, body []byte) error {
	if a.S3 == nil {
		return errors.New("GuardDuty S3 destination owner is unavailable")
	}
	bucket, _, err := destinationS3Location(d)
	if err != nil {
		return err
	}
	return a.put(destinationS3Context(ctx, d), d, bucket, key, body, true)
}

func (a GuardDutyDestinations) put(ctx context.Context, d guardduty.PublishingDestination, bucket, key string, body []byte, findings bool) error {
	in := &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body, ServerSideEncryption: new(api.ServerSideEncryption("aws:kms")), SSEKMSKeyId: new(api.SSEKMSKeyId(d.KMSKeyARN)), ContentType: new(api.ContentType("application/octet-stream"))}
	if findings {
		in.ContentType = new(api.ContentType("application/x-ndjson"))
		in.ContentEncoding = new(api.ContentEncoding("gzip"))
	}
	_, rejected := a.S3.PutObject(ctx, in)
	if rejected != nil {
		return destinationS3Rejection(rejected)
	}
	return nil
}
