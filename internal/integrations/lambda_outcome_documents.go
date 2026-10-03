package integrations

import (
	"context"

	s3api "stackd/internal/awsapi/s3"
	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

func (a *LambdaOutcomes) CheckStream(ctx context.Context, function lambda.FunctionKey, roleARN string, mapping lambda.EventSourceMappingKey, destinationARN string) *awswire.Error {
	return a.checkDestination(ctx, function, roleARN, destinationARN, "aws/lambda/"+mapping.UUID+"/*")
}

func (a *LambdaOutcomes) SendStream(ctx context.Context, delivery lambda.StreamFailure) *awswire.Error {
	target, _ := arn.Parse(delivery.DestinationARN)
	metadata := awsctx.FromContext(ctx)
	metadata.ParentEventID = delivery.ParentEventID
	ctx = awsctx.WithMetadata(ctx, metadata)
	ctx, rejected := a.roleContext(ctx, delivery.Function.FunctionKey, delivery.RoleARN, target.Region)
	if rejected != nil {
		return rejected
	}
	key := ""
	if target.Service == "s3" {
		key = "aws/lambda/" + delivery.Mapping.UUID + "/" + delivery.ShardID + "/" + delivery.CreatedAt.UTC().Format("2006/01/02/2006-01-02T15.04.05") + "-" + delivery.ID
	}
	return a.sendDocument(ctx, target, delivery.DestinationARN, delivery.Payload, nil, key)
}

// sendDocument shares destination commands after the caller has selected its
// execution-role context and native payload. Source-specific envelopes and S3
// key layouts remain with their respective invocation owner.
func (a *LambdaOutcomes) sendDocument(ctx context.Context, target arn.ARN, destinationARN string, payload []byte, attributes snsapi.MessageAttributeMap, objectKey string) *awswire.Error {
	switch target.Service {
	case "sqs":
		_, rejected := a.SQS.SendToQueue(ctx, destinationARN, &sqsapi.SendMessageInput{MessageBody: new(sqsapi.String(payload)), MessageAttributes: sqsMessageAttributes(attributes)})
		return rejected
	case "sns":
		_, rejected := a.SNS.Publish(ctx, &snsapi.PublishInput{TopicArn: new(snsapi.TopicARN(destinationARN)), Message: new(snsapi.Message(payload)), MessageAttributes: attributes})
		return rejected
	case "s3":
		_, rejected := a.S3.PutObject(ctx, &s3api.PutObjectInput{Bucket: new(s3api.BucketName(target.Resource)), Key: new(s3api.ObjectKey(objectKey)), Body: payload, ContentType: new(s3api.ContentType("application/octet-stream"))})
		return rejected
	default:
		return &awswire.Error{Code: "NotImplementedException", Message: "Unsupported Lambda document destination.", StatusCode: 501}
	}
}
