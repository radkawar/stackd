package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/glue"
)

// GlueEvents admits service-owned state changes in the source transaction. The
// existing EventBridge owner handles rule matching, delivery and authorization.
type GlueEvents struct {
	Publisher EventBridgeEventPublisher
	Clock     clock.Clock
}

func (a GlueEvents) publish(ctx context.Context, scope glue.Scope, resource string, resources []string, detailType string, detail any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "glue.amazonaws.com", SourceARN: resource, Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID:     uuid.NewString(),
		Bus:    eventbridge.BusKey{Scope: eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region}, Name: "default"},
		Source: "aws.glue", DetailType: detailType, Detail: string(body),
		Resources: resources, Time: a.Clock.Now(), Account: scope.AccountID, RequestID: origin.RequestID,
	})
}

func (a GlueEvents) Publish(ctx context.Context, crawler glue.CrawlerRecord, state, message string) error {
	// Glue does not document a crawler Stopped state-change event. Cancellation
	// remains visible through GetCrawler/ListCrawls rather than an invented event.
	switch state {
	case "Started", "Succeeded", "Failed":
	default:
		return fmt.Errorf("unsupported Glue crawler event state %q", state)
	}
	return a.publish(ctx, crawler.Key.Scope, crawler.Key.ARN("crawler"), []string{}, "Glue Crawler State Change", struct {
		CrawlerName string `json:"crawlerName"`
		State       string `json:"state"`
		Message     string `json:"message,omitempty"`
	}{crawler.Key.Name, state, message})
}

func (a GlueEvents) PublishJob(ctx context.Context, run glue.JobRunRecord) error {
	// STARTING/RUNNING/STOPPING use the distinct delayed-notification event,
	// never the terminal Glue Job State Change event.
	switch run.State {
	case "SUCCEEDED", "FAILED", "TIMEOUT", "STOPPED":
	default:
		return nil
	}
	severity := "INFO"
	if run.State == "FAILED" || run.State == "TIMEOUT" {
		severity = "ERROR"
	}
	message := run.Error
	if run.State == "SUCCEEDED" {
		message = "Job run succeeded"
	}
	return a.publish(ctx, run.Key.Scope, run.Key.ARN("job"), []string{}, "Glue Job State Change", struct {
		JobName  string `json:"jobName"`
		JobRunID string `json:"jobRunId"`
		State    string `json:"state"`
		Severity string `json:"severity"`
		Message  string `json:"message,omitempty"`
	}{run.Key.Name, run.ID, run.State, severity, message})
}

func (a GlueEvents) PublishCatalog(ctx context.Context, event glue.CatalogEvent) error {
	catalog := glue.CatalogKey{Scope: event.Scope, CatalogID: event.CatalogID}
	if event.TableName == "" {
		resource := catalog.ResourceARN("database", event.DatabaseName)
		resources := []string{resource}
		tables := event.ChangedTables
		if len(tables) == 0 {
			tables = []string{}
		} else {
			resources = make([]string, len(tables))
			for i, table := range tables {
				resources[i] = catalog.ResourceARN("table", event.DatabaseName+"/"+table)
			}
		}
		return a.publish(ctx, event.Scope, resource, resources, "Glue Data Catalog Database State Change", struct {
			TypeOfChange  string   `json:"typeOfChange"`
			CatalogID     string   `json:"catalogId"`
			DatabaseName  string   `json:"databaseName"`
			ChangedTables []string `json:"changedTables"`
		}{event.Operation, event.CatalogID, event.DatabaseName, tables})
	}
	partitions := make([]string, len(event.ChangedPartitions))
	for i, values := range event.ChangedPartitions {
		partitions[i] = strings.Join(values, ",")
	}
	resource := catalog.ResourceARN("table", event.DatabaseName+"/"+event.TableName)
	return a.publish(ctx, event.Scope, resource, []string{resource}, "Glue Data Catalog Table State Change", struct {
		TypeOfChange      string   `json:"typeOfChange"`
		CatalogID         string   `json:"catalogId"`
		DatabaseName      string   `json:"databaseName"`
		TableName         string   `json:"tableName"`
		ChangedPartitions []string `json:"changedPartitions"`
	}{event.Operation, event.CatalogID, event.DatabaseName, event.TableName, partitions})
}
