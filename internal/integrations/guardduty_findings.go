package integrations

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/guardduty"
)

// GuardDutyFindings admits finding events atomically with the producer's
// publication cursor. EventBridge owns current target authority and real delivery.
type GuardDutyFindings struct{ Publisher EventBridgeEventPublisher }

func (a GuardDutyFindings) PublishFinding(ctx context.Context, record guardduty.Finding, finding api.Finding) error {
	if a.Publisher == nil {
		return errors.New("GuardDuty EventBridge publisher is unavailable")
	}
	model, _ := awscatalog.LookupService("guardduty")
	body, err := awsapi.EncodeDocument(model, "com.amazonaws.guardduty#Finding", finding, nil)
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	if record.Observation.EventID != "" {
		origin.ParentEventID = record.Observation.EventID
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: record.Partition, AccountID: record.AccountID, Region: record.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: guardduty.ServicePrincipal, SourceARN: stringValue(finding.Arn), Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: record.Partition, Account: record.AccountID, Region: record.Region}, Name: "default"},
		Source: "aws.guardduty", DetailType: "GuardDuty Finding", Detail: string(body), Resources: []string{}, Time: record.Updated, Account: record.AccountID, RequestID: origin.RequestID,
	})
}
