package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/ssm"
)

// SSMEvents admits Parameter Store changes and policy actions in their resource transaction.
type SSMEvents struct{ Publisher EventBridgeEventPublisher }

func (a SSMEvents) PublishEvent(ctx context.Context, event ssm.Event) error {
	origin := awsctx.FromContext(ctx)
	scope := event.Scope
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "ssm.amazonaws.com", Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: event.ID, Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region}, Name: "default"}, Source: "aws.ssm", DetailType: event.DetailType, Detail: string(event.Detail), Resources: event.Resources, Time: event.At, Account: scope.AccountID, RequestID: origin.RequestID})
}
