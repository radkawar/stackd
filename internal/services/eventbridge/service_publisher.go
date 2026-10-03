package eventbridge

import (
	"context"
	"fmt"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/journal"
)

// ServicePublisher admits trusted first-party events without customer PutEvents
// authorization. Producers own source eligibility; ordinary target commands
// enforce delivery permissions after admission.
type ServicePublisher struct {
	Repository Repository
	Events     Events
	Clock      clock.Clock
	Metrics    MetricPublisher
}

func (p ServicePublisher) PublishAPICall(ctx context.Context, event journal.Event) error {
	call := event.APICallCompleted
	namespace := ""
	for _, service := range awscatalog.Services() {
		if service.CloudTrailEventSource == call.EventSource {
			namespace = service.ARNNamespace
			break
		}
	}
	if namespace == "" {
		return fmt.Errorf("no generated EventBridge source for %q", call.EventSource)
	}
	detail, err := apievents.CloudTrailRecord(event)
	if err != nil {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: event.Partition, AccountID: event.AccountID, Region: event.Region, RequestID: event.RequestID, ParentEventID: call.EventID, ServicePrincipal: awsctx.ServicePrincipal{Name: call.EventSource}})
	record := EventRecord{ID: identifier(), Bus: BusKey{Scope: Scope{Partition: event.Partition, Account: event.AccountID, Region: event.Region}, Name: "default"}, Source: "aws." + namespace, DetailType: "AWS API Call via CloudTrail", Detail: string(detail), Time: event.At, Account: event.AccountID, RequestID: event.RequestID}
	if call.ServiceEvent {
		record.DetailType = "AWS Service Event via CloudTrail"
	}
	return p.publishEvent(ctx, record, call.Category == journal.CategoryManagement && call.ReadOnly)
}

// PublishEvent admits a native service event using its producer-owned identity,
// document and scope. Its context retains the source transaction and causality.
func (p ServicePublisher) PublishEvent(ctx context.Context, event EventRecord) error {
	return p.publishEvent(ctx, event, false)
}

func (p ServicePublisher) publishEvent(ctx context.Context, event EventRecord, managementRead bool) error {
	event.Accepted = p.Clock.Now()
	event.WireID, event.Region = event.ID, event.Bus.Region
	return p.Repository.Update(ctx, func(tx Transaction) error {
		return commitEvent(tx, event, p.Events, p.Metrics, eventSelection{ManagementRead: managementRead})
	})
}
