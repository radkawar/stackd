package integrations

import (
	"context"
	"strconv"

	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/kafka"
)

// KafkaMetrics publishes actual broker observations in their owning cluster's
// scope. It does not grant customers PutMetricData or synthesize missing values.
type KafkaMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

func (a KafkaMetrics) PublishKafkaMetrics(ctx context.Context, scope kafka.Scope, clusterName string, measurements []kafka.BrokerMetric) error {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = scope.Partition, scope.AccountID, scope.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	data := make([]cw.MetricDatum, 0, min(1000, len(measurements)))
	for _, measurement := range measurements {
		data = append(data, cw.MetricDatum{
			MetricName: new(cw.MetricName(measurement.Name)),
			Timestamp:  new(measurement.Timestamp),
			Unit:       new(cw.StandardUnit(measurement.Unit)),
			Value:      new(cw.DatapointValue(measurement.Value)),
			Dimensions: cw.Dimensions{
				{Name: new(cw.DimensionName("Cluster Name")), Value: new(cw.DimensionValue(clusterName))},
				{Name: new(cw.DimensionName("Broker ID")), Value: new(cw.DimensionValue(strconv.FormatInt(int64(measurement.BrokerID), 10)))},
			},
		})
		if len(data) == cap(data) {
			if err := a.Metrics.Publish(ctx, "AWS/Kafka", data); err != nil {
				return err
			}
			data = data[:0]
		}
	}
	if len(data) > 0 {
		return a.Metrics.Publish(ctx, "AWS/Kafka", data)
	}
	return nil
}
