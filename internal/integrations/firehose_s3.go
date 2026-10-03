package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/clock"
	api "stackd/internal/awsapi/firehose"
	logsapi "stackd/internal/awsapi/logs"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/firehose"
)

// FirehoseS3Commands keeps bucket authorization and actual object writes in S3.
type FirehoseS3Commands interface {
	GetBucketLocation(context.Context, *s3api.GetBucketLocationInput) (*s3api.GetBucketLocationOutput, *awswire.Error)
	PutObject(context.Context, *s3api.PutObjectInput) (*s3api.PutObjectOutput, *awswire.Error)
}

type FirehoseLogCommands interface {
	PutLogEvents(context.Context, *logsapi.PutLogEventsRequest) (*logsapi.PutLogEventsResponse, *awswire.Error)
}

type FirehoseS3 struct {
	Roles    ServiceRoles
	S3       FirehoseS3Commands
	Logs     FirehoseLogCommands
	Clock    clock.Clock
	sessions serviceRoleSessions
}

func firehosePrincipal(key firehose.StreamKey) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "firehose.amazonaws.com", SourceARN: key.ARN(), Type: "AWSService"}
}
func firehoseContext(ctx context.Context, key firehose.StreamKey, parent string) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = key.Partition, key.AccountID, key.Region
	metadata.ParentEventID = parent
	return awsctx.WithMetadata(ctx, metadata)
}
func firehoseAssumptionError(role string, rejected *awswire.Error) *awswire.Error {
	if rejected.StatusCode >= 500 {
		return rejected
	}
	return &awswire.Error{Code: "AccessDeniedException", Message: "Firehose is unable to assume role " + role + ". Please check the role provided.", StatusCode: 400}
}

func (a *FirehoseS3) Validate(ctx context.Context, key firehose.StreamKey, destination api.ExtendedS3DestinationDescription) *awswire.Error {
	role := string(*destination.RoleARN)
	credential, rejected := a.Roles.assume(ctx, firehosePrincipal(key), role, identity.RoleSessionSpec{SessionName: "AWSFirehoseToS3"}, key.AccountID)
	if rejected != nil {
		rejected = firehoseAssumptionError(role, rejected)
		if rejected.StatusCode < 500 {
			rejected.Code = "InvalidArgumentException"
		}
		return rejected
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, key.Region, "firehose.amazonaws.com")
	if rejected != nil {
		return rejected
	}
	bucket, err := arn.Parse(string(*destination.BucketARN))
	if err != nil || bucket.Service != "s3" || bucket.Partition != key.Partition || bucket.AccountID != "" || bucket.Region != "" {
		return &awswire.Error{Code: "InvalidArgumentException", Message: "The S3 bucket ARN is invalid.", StatusCode: 400}
	}
	_, rejected = a.S3.GetBucketLocation(ctx, &s3api.GetBucketLocationInput{Bucket: new(s3api.BucketName(bucket.Resource))})
	if rejected == nil {
		return nil
	}
	if rejected.Code == "NoSuchBucket" {
		return &awswire.Error{Code: "InvalidArgumentException", Message: "S3 Bucket " + bucket.Resource + " does not exist.", StatusCode: 400}
	}
	if rejected.StatusCode >= 500 {
		return rejected
	}
	return &awswire.Error{Code: "InvalidArgumentException", Message: rejected.Message, StatusCode: 400}
}
func (a *FirehoseS3) Write(ctx context.Context, buffer firehose.BufferRecord, body []byte) *awswire.Error {
	ctx = firehoseContext(ctx, buffer.Stream, buffer.ParentEventID)
	destination := buffer.Configuration
	ctx, err := a.sessions.context(ctx, a.Roles, firehosePrincipal(buffer.Stream), string(*destination.RoleARN), "AWSFirehoseToS3", buffer.Stream.AccountID)
	if err != nil {
		return serviceRoleFailure(err)
	}
	bucket := strings.TrimPrefix(string(*destination.BucketARN), "arn:"+buffer.Stream.Partition+":s3:::")
	input := &s3api.PutObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(buffer.ObjectKey)), Body: body, ACL: new(s3api.ObjectCannedACL("bucket-owner-full-control")), ContentType: new(s3api.ContentType("application/octet-stream"))}
	if encryption := destination.EncryptionConfiguration; encryption != nil && encryption.KMSEncryptionConfig != nil {
		input.ServerSideEncryption = new(s3api.ServerSideEncryption("aws:kms"))
		input.SSEKMSKeyId = new(s3api.SSEKMSKeyId(*encryption.KMSEncryptionConfig.AWSKMSKeyARN))
	}
	if destination.CompressionFormat != nil {
		switch *destination.CompressionFormat {
		case "GZIP":
			input.ContentEncoding = new(s3api.ContentEncoding("gzip"))
		case "ZIP":
			input.ContentEncoding = new(s3api.ContentEncoding("zip"))
		case "Snappy":
			input.ContentEncoding = new(s3api.ContentEncoding("snappy-java"))
		case "HADOOP_SNAPPY":
			input.ContentEncoding = new(s3api.ContentEncoding("hadoop-snappy"))
		}
	}
	_, rejected := a.S3.PutObject(ctx, input)
	return rejected
}
func (a *FirehoseS3) Report(ctx context.Context, stream firehose.StreamRecord, code, message string) error {
	options := stream.Destination.CloudWatchLoggingOptions
	if options == nil || options.Enabled == nil || !bool(*options.Enabled) {
		return nil
	}
	ctx = firehoseContext(ctx, stream.Key, awsctx.FromContext(ctx).ParentEventID)
	ctx, err := a.sessions.context(ctx, a.Roles, firehosePrincipal(stream.Key), string(*stream.Destination.RoleARN), "Firehose", stream.Key.AccountID)
	if err != nil {
		return err
	}
	// Native source diagnostics use a number; S3 delivery diagnostics use a string.
	var version any = stream.Version
	if strings.HasPrefix(code, "S3.") {
		version = strconv.FormatInt(stream.Version, 10)
	}
	body, err := json.Marshal(struct {
		StreamARN   string `json:"deliveryStreamARN"`
		Destination string `json:"destination"`
		Version     any    `json:"deliveryStreamVersionId"`
		Message     string `json:"message"`
		Code        string `json:"errorCode"`
	}{stream.Key.ARN(), string(*stream.Destination.BucketARN), version, message, code})
	if err != nil {
		return err
	}
	_, rejected := a.Logs.PutLogEvents(ctx, &logsapi.PutLogEventsRequest{LogGroupName: new(logsapi.LogGroupName(*options.LogGroupName)), LogStreamName: new(logsapi.LogStreamName(*options.LogStreamName)), LogEvents: logsapi.InputLogEvents{{Timestamp: new(logsapi.Timestamp(a.Clock.Now().UnixMilli())), Message: new(logsapi.EventMessage(string(body)))}}})
	if rejected != nil {
		return rejected
	}
	return nil
}
