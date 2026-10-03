package integrations

import (
	"context"
	"encoding/json"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudtrail"
)

// CloudTrailSNS uses the ordinary SNS command for both native validation
// messages and delivered log-object notifications. SNS owns subscriber delivery.
type CloudTrailSNS struct{ SNS SNSPublisher }

var _ cloudtrail.NotificationDestination = CloudTrailSNS{}

func (a CloudTrailSNS) Validate(ctx context.Context, trail cloudtrail.TrailRecord, parent string) *awswire.Error {
	rejected := a.publish(ctx, trail.Key, trail.SNSTopicARN(), "CloudTrail validation message.", parent)
	if rejected != nil && (rejected.Code == "NotFound" || rejected.Code == "AuthorizationError") {
		return &awswire.Error{Code: "InsufficientSnsTopicPolicyException", Message: "SNS Topic does not exist or the topic policy is incorrect!", StatusCode: 400, Cause: rejected}
	}
	return rejected
}

func (a CloudTrailSNS) Write(ctx context.Context, delivery cloudtrail.DeliveryRecord, topicARN, parent string) *awswire.Error {
	body, _ := json.Marshal(struct {
		Bucket string    `json:"s3Bucket"`
		Keys   [1]string `json:"s3ObjectKey"`
	}{delivery.Bucket, [1]string{delivery.ObjectKey}})
	return a.publish(ctx, delivery.Trail, topicARN, string(body), parent)
}

func (a CloudTrailSNS) publish(ctx context.Context, trail cloudtrail.TrailKey, topicARN, message, parent string) *awswire.Error {
	ctx = trailContext(ctx, trail, parent)
	metadata := awsctx.FromContext(ctx)
	// The trail boundary has validated this ARN. Cross-Region topics use the
	// destination Region while SourceArn remains the original trail ARN.
	metadata.Region = strings.SplitN(topicARN, ":", 6)[3]
	ctx = awsctx.WithMetadata(ctx, metadata)
	_, rejected := a.SNS.Publish(ctx, &api.PublishInput{
		TopicArn: new(api.TopicARN(topicARN)), Message: new(api.Message(message)),
	})
	return rejected
}
