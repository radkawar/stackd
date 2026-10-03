package integrations

import (
	"context"
	"fmt"

	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/opensearch"
)

// OpenSearchMetrics publishes measured native values, not provisioned cloud
// instance/storage capacity or synthetic search counters.
type OpenSearchMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

func (a OpenSearchMetrics) PublishOpenSearchMetric(ctx context.Context, sample opensearch.Metric) error {
	unit := cw.StandardUnitCount
	switch sample.Name {
	case "JVMMemoryPressure":
		unit = cw.StandardUnitPercent
	case "Nodes", "SearchableDocuments", "ClusterStatus.green", "ClusterStatus.yellow", "ClusterStatus.red":
	default:
		return fmt.Errorf("unsupported native OpenSearch metric %q", sample.Name)
	}
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = sample.Domain.Partition, sample.Domain.AccountID, sample.Domain.Region
	ctx = awsctx.WithMetadata(ctx, m)
	return a.Metrics.Publish(ctx, "AWS/ES", []cw.MetricDatum{{MetricName: new(cw.MetricName(sample.Name)), Timestamp: new(sample.At), Unit: &unit, Value: new(cw.DatapointValue(sample.Value)), Dimensions: cw.Dimensions{{Name: new(cw.DimensionName("DomainName")), Value: new(cw.DimensionValue(sample.Domain.Name))}, {Name: new(cw.DimensionName("ClientId")), Value: new(cw.DimensionValue(sample.Domain.AccountID))}}}})
}
