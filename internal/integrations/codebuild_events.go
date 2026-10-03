package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/eventbridge"
)

// CodeBuildEvents joins state-change admission to the source transaction.
type CodeBuildEvents struct{ Publisher EventBridgeEventPublisher }

func (a CodeBuildEvents) PublishBuildEvent(ctx context.Context, event codebuild.BuildEvent) error {
	origin := awsctx.FromContext(ctx)
	key := event.Key
	resource := key.ARN()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "codebuild.amazonaws.com", SourceARN: resource, Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: event.ID, Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: key.Partition, Account: key.AccountID, Region: key.Region}, Name: "default"}, Source: "aws.codebuild", DetailType: "CodeBuild Build State Change", Detail: string(event.Detail), Resources: []string{resource}, Time: event.At, Account: key.AccountID, RequestID: origin.RequestID})
}
