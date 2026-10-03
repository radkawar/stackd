package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/ecs"
	"stackd/internal/services/eventbridge"
)

// ECSEvents admits task- and service-owned native events in the source transaction,
// independently of CloudTrail trails and customer PutEvents authorization.
type ECSEvents struct {
	Publisher EventBridgeEventPublisher
}

var _ ecs.TaskEventPublisher = ECSEvents{}
var _ ecs.ServiceEventPublisher = ECSEvents{}

func (a ECSEvents) PublishTaskEvent(ctx context.Context, event ecs.TaskEvent) error {
	origin := awsctx.FromContext(ctx)
	key := event.Key
	taskARN := key.ARN()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "ecs.amazonaws.com", SourceARN: taskARN, Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: event.ID,
		Bus: eventbridge.BusKey{
			Scope: eventbridge.Scope{Partition: key.Partition, Account: key.AccountID, Region: key.Region},
			Name:  "default",
		},
		Source: "aws.ecs", DetailType: "ECS Task State Change", Detail: string(event.Detail),
		Resources: []string{taskARN}, Time: event.At,
		Account: key.AccountID, RequestID: origin.RequestID,
	})
}

func (a ECSEvents) PublishServiceEvent(ctx context.Context, event ecs.ServiceEvent) error {
	origin := awsctx.FromContext(ctx)
	key := event.Key
	serviceARN := key.ARN()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "ecs.amazonaws.com", SourceARN: serviceARN, Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: event.ID,
		Bus: eventbridge.BusKey{
			Scope: eventbridge.Scope{Partition: key.Partition, Account: key.AccountID, Region: key.Region},
			Name:  "default",
		},
		Source: "aws.ecs", DetailType: event.DetailType, Detail: string(event.Detail),
		Resources: []string{serviceARN}, Time: event.At,
		Account: key.AccountID, RequestID: origin.RequestID,
	})
}
