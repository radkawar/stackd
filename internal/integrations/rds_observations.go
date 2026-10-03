package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/rds"
)

// RDSEvents admits documented native lifecycle projections in the same shared
// transaction as the source transition. The existing EventBridge owner delivers.
type RDSEvents struct{ Publisher EventBridgeEventPublisher }

func (a RDSEvents) PublishRDSEvent(ctx context.Context, event rds.RDSEvent) error {
	id, category, message := rdsEventDescription(event)
	if id == "" {
		return nil
	}
	resource, err := arn.Parse(event.ARN)
	if err != nil {
		return err
	}
	typeNames := map[string][2]string{
		"db":               {"RDS DB Instance Event", "DB_INSTANCE"},
		"cluster":          {"RDS DB Cluster Event", "DB_CLUSTER"},
		"snapshot":         {"RDS DB Snapshot Event", "DB_SNAPSHOT"},
		"cluster-snapshot": {"RDS DB Cluster Snapshot Event", "DB_CLUSTER_SNAPSHOT"},
	}
	names, ok := typeNames[event.Kind]
	if !ok {
		return fmt.Errorf("unknown RDS event resource kind %q", event.Kind)
	}
	detail, err := json.Marshal(struct {
		Categories []string `json:"EventCategories"`
		SourceType string   `json:"SourceType"`
		SourceARN  string   `json:"SourceArn"`
		Date       string   `json:"Date"`
		Message    string   `json:"Message"`
		Identifier string   `json:"SourceIdentifier"`
		EventID    string   `json:"EventID"`
	}{[]string{category}, names[1], event.ARN, event.At.UTC().Format(time.RFC3339Nano), message, event.Identifier, id})
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: resource.Partition, AccountID: resource.AccountID, Region: resource.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: rdsServicePrincipal, SourceARN: event.ARN, Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: resource.Partition, Account: resource.AccountID, Region: resource.Region}, Name: "default"}, Source: "aws.rds", DetailType: names[0], Detail: string(detail), Resources: []string{event.ARN}, Time: event.At, Account: resource.AccountID, RequestID: origin.RequestID})
}

// Only events with a documented native meaning are emitted. Native engine
// failures and restore internals have no invented event identifier.
func rdsEventDescription(e rds.RDSEvent) (string, string, string) {
	switch e.Kind {
	case "db":
		switch e.Operation {
		case "create":
			if e.Status == "available" {
				return "RDS-EVENT-0005", "creation", "DB instance created."
			}
		case "start":
			if e.Status == "available" {
				return "RDS-EVENT-0088", "notification", "DB instance started."
			}
		case "stop":
			if e.Status == "stopped" {
				return "RDS-EVENT-0087", "notification", "DB instance stopped."
			}
		case "delete":
			if e.Status == "deleted" {
				return "RDS-EVENT-0003", "deletion", "DB instance deleted."
			}
		case "password":
			if e.Status == "available" {
				return "RDS-EVENT-0016", "configuration change", "Reset master credentials."
			}
		case "parameters":
			if e.Status == "available" {
				return "RDS-EVENT-0092", "configuration change", "Finished updating DB parameter group."
			}
		}
	case "cluster":
		switch e.Operation {
		case "create":
			if e.Status == "available" {
				return "RDS-EVENT-0170", "creation", "DB cluster created."
			}
		case "start":
			if e.Status == "available" {
				return "RDS-EVENT-0151", "notification", "DB cluster started."
			}
		case "stop":
			if e.Status == "stopped" {
				return "RDS-EVENT-0150", "notification", "DB cluster stopped."
			}
		case "password":
			if e.Status == "available" {
				return "RDS-EVENT-0016", "configuration change", "Reset master credentials."
			}
		}
	case "snapshot":
		if e.Operation == "snapshot" && e.Status == "available" {
			return "RDS-EVENT-0042", "backup", "Manual snapshot created."
		}
	case "cluster-snapshot":
		if e.Operation == "snapshot" && e.Status == "available" {
			return "RDS-EVENT-0075", "backup", "Manual cluster snapshot created."
		}
	}
	return "", "", ""
}

// RDSMetrics forwards measured database samples, never modeled instance sizes
// or synthetic engine CPU/storage values, into the CloudWatch transaction owner.
type RDSMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

func (a RDSMetrics) PublishRDSMetric(ctx context.Context, sample rds.RDSMetric) error {
	if sample.Name != "DatabaseConnections" {
		return fmt.Errorf("unsupported RDS native metric %q", sample.Name)
	}
	resource, err := arn.Parse(sample.ARN)
	if err != nil {
		return err
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = resource.Partition, resource.AccountID, resource.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	return a.Metrics.Publish(ctx, "AWS/RDS", []cw.MetricDatum{{MetricName: new(cw.MetricName(sample.Name)), Timestamp: new(sample.At), Unit: new(cw.StandardUnitCount), Value: new(cw.DatapointValue(sample.Value)), Dimensions: cw.Dimensions{{Name: new(cw.DimensionName("DBInstanceIdentifier")), Value: new(cw.DimensionValue(sample.Identifier))}}}})
}
