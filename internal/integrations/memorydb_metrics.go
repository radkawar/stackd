package integrations

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/memorydb"
)

// MemoryDBMetrics publishes native gauges to the existing CloudWatch owner.
// CPU, distributed-log durability and AZ-level availability are not simulated.
type MemoryDBMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

func (a MemoryDBMetrics) PublishMemoryDBMetric(ctx context.Context, sample memorydb.Metric) error {
	unit := cw.StandardUnitCount
	switch sample.Name {
	case "CurrConnections":
	case "BytesUsedForMemoryDB":
		unit = cw.StandardUnitBytes
	default:
		return fmt.Errorf("unsupported MemoryDB native metric %q", sample.Name)
	}
	resource, e := arn.Parse(sample.ARN)
	if e != nil {
		return e
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = resource.Partition, resource.AccountID, resource.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	return a.Metrics.Publish(ctx, "AWS/MemoryDB", []cw.MetricDatum{{MetricName: new(cw.MetricName(sample.Name)), Timestamp: new(sample.At), Unit: new(unit), Value: new(cw.DatapointValue(sample.Value)), Dimensions: cw.Dimensions{{Name: new(cw.DimensionName("ClusterName")), Value: new(cw.DimensionValue(sample.ClusterName))}}}})
}
