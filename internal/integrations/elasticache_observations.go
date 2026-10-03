package integrations

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/elasticache"
)

// ElastiCacheMetrics publishes observed gauges from real native INFO output.
// No CPU, cache capacity utilization, or hit deltas are fabricated.
type ElastiCacheMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

func (a ElastiCacheMetrics) PublishElastiCacheMetric(ctx context.Context, sample elasticache.Metric) error {
	unit := cw.StandardUnitCount
	switch sample.Name {
	case "CurrConnections":
	case "BytesUsedForCache":
		unit = cw.StandardUnitBytes
	default:
		return fmt.Errorf("unsupported ElastiCache gauge %q", sample.Name)
	}
	resource, e := arn.Parse(sample.ARN)
	if e != nil {
		return e
	}
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = resource.Partition, resource.AccountID, resource.Region
	ctx = awsctx.WithMetadata(ctx, m)
	dimension := "CacheClusterId"
	if len(resource.Resource) >= 17 && resource.Resource[:17] == "replicationgroup:" {
		dimension = "ReplicationGroupId"
	}
	return a.Metrics.Publish(ctx, "AWS/ElastiCache", []cw.MetricDatum{{MetricName: new(cw.MetricName(sample.Name)), Timestamp: new(sample.At), Unit: &unit, Value: new(cw.DatapointValue(sample.Value)), Dimensions: cw.Dimensions{{Name: new(cw.DimensionName(dimension)), Value: new(cw.DimensionValue(sample.Identifier))}}}})
}

// TODO: Comeback wire requested SNS cache notifications through its actual
// owner; ElastiCache API activity already uses the shared CloudTrail recorder.
// Do not synthesize direct EventBridge lifecycle events from local transitions.
