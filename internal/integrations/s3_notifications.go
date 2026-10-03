package integrations

import (
	"context"
	"time"

	"github.com/google/uuid"

	snsapi "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/s3"
)

// S3Notifications crosses the source transaction boundary through the ordinary
// recipient commands. SNS fanout and Lambda execution remain recipient-owned.
type S3Notifications struct {
	SNS    SNSPublisher
	SQS    SQSSender
	Lambda LambdaSubscriptionInvoker
}

var _ s3.NotificationDestinations = (*S3Notifications)(nil)

func (a *S3Notifications) Validate(ctx context.Context, delivery s3.NotificationDelivery) (string, *awswire.Error) {
	ctx = s3NotificationContext(ctx, delivery)
	if delivery.Protocol == s3.NotificationLambda {
		return "", a.Lambda.CheckInvoke(ctx, delivery.DestinationARN)
	}
	return a.publish(ctx, delivery)
}

func (a *S3Notifications) Send(ctx context.Context, delivery s3.NotificationDelivery) *awswire.Error {
	ctx = s3NotificationContext(ctx, delivery)
	if delivery.Protocol == s3.NotificationLambda {
		_, rejected := a.Lambda.InvokeEvent(ctx, delivery.DestinationARN, []byte(delivery.Payload), "")
		return rejected
	}
	_, wire := a.publish(ctx, delivery)
	return wire
}

func (a *S3Notifications) publish(ctx context.Context, delivery s3.NotificationDelivery) (string, *awswire.Error) {
	switch delivery.Protocol {
	case s3.NotificationSNS:
		out, wire := a.SNS.Publish(ctx, &snsapi.PublishInput{
			TopicArn: new(snsapi.TopicARN(delivery.DestinationARN)), Message: new(snsapi.Message(delivery.Payload)),
			Subject: new(snsapi.Subject("Amazon S3 Notification")),
		})
		if wire != nil {
			return "", wire
		}
		return string(*out.MessageId), nil
	case s3.NotificationSQS:
		out, wire := a.SQS.SendToQueue(ctx, delivery.DestinationARN, &sqsapi.SendMessageInput{MessageBody: new(sqsapi.String(delivery.Payload))})
		if wire != nil {
			return "", wire
		}
		return string(*out.MessageId), nil
	default:
		return "", &awswire.Error{Code: "NotImplemented", Message: "Unsupported S3 notification destination.", StatusCode: 501}
	}
}

func s3NotificationContext(ctx context.Context, delivery s3.NotificationDelivery) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: delivery.Bucket.Partition, AccountID: delivery.AccountID, Region: delivery.Region,
		RequestID: delivery.RequestID, ParentEventID: delivery.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "s3.amazonaws.com", SourceARN: delivery.Bucket.ARN(), Type: "AssumedRole"},
	})
}

// S3Events commits native object events on the bucket owner's default bus in
// the same transaction as the source mutation, without customer PutEvents.
type S3Events struct{ Publisher EventBridgeEventPublisher }

var _ s3.NativeObjectEvents = S3Events{}

func (a S3Events) PublishObjectEvent(ctx context.Context, bucket s3.BucketRecord, at time.Time, detailType, detail, parent string) error {
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: bucket.Key.Partition, AccountID: bucket.AccountID, Region: bucket.Region,
		RequestID: origin.RequestID, ParentEventID: parent,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "s3.amazonaws.com", SourceARN: bucket.Key.ARN(), Type: "AssumedRole"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: bucket.Key.Partition, Account: bucket.AccountID, Region: bucket.Region}, Name: "default"},
		Source: "aws.s3", DetailType: detailType, Detail: detail, Resources: []string{bucket.Key.ARN()},
		Time: at, Account: bucket.AccountID, RequestID: origin.RequestID,
	})
}
