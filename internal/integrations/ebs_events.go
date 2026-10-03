package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/ebs"
	"stackd/internal/services/eventbridge"
)

// EBSEvents admits EBS-owned native events in the lifecycle transaction,
// independently of CloudTrail trails and customer PutEvents authorization.
type EBSEvents struct {
	Publisher EventBridgeEventPublisher
}

var _ ebs.NotificationPublisher = EBSEvents{}

func (a EBSEvents) PublishEBSNotification(ctx context.Context, event ebs.Notification) error {
	origin := awsctx.FromContext(ctx)
	key := event.Scope
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "ec2.amazonaws.com", SourceARN: event.Resources[0], Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: event.ID,
		Bus: eventbridge.BusKey{
			Scope: eventbridge.Scope{Partition: key.Partition, Account: key.AccountID, Region: key.Region},
			Name:  "default",
		},
		Source: "aws.ec2", DetailType: event.DetailType, Detail: string(event.Detail),
		Resources: event.Resources, Time: event.At,
		Account: key.AccountID, RequestID: origin.RequestID,
	})
}
