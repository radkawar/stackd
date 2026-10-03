package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/ecr"
	"stackd/internal/services/eventbridge"
)

// ECREvents admits native ECR service events within the resource transaction.
type ECREvents struct{ Publisher EventBridgeEventPublisher }

func (a ECREvents) PublishEvent(ctx context.Context, event ecr.Event) error {
	origin := awsctx.FromContext(ctx)
	scope := event.Scope
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "ecr.amazonaws.com", Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: event.ID, Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region}, Name: "default"}, Source: "aws.ecr", DetailType: event.DetailType, Detail: string(event.Detail), Resources: event.Resources, Time: event.At, Account: scope.AccountID, RequestID: origin.RequestID})
}
