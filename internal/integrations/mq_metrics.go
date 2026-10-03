package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/mq"
)

// MQMetrics publishes native queue observations through the CloudWatch owner in
// the broker's scope. These are service observations, not caller PutMetricData
// requests or uses of RabbitMQ's logging service-linked role.
type MQMetrics struct {
	Metrics interface {
		Publish(context.Context, string, []cw.MetricDatum) error
	}
}

// PublishMQMetrics projects one complete native engine snapshot in broker scope.
func (a MQMetrics) PublishMQMetrics(ctx context.Context, broker mq.BrokerRecord, sample mq.MetricSnapshot, at time.Time) error {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = broker.Partition, broker.AccountID, broker.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	switch {
	case broker.Engine == "RABBITMQ" && sample.RabbitMQ != nil && sample.ActiveMQ == nil:
		return a.publishRabbitMQMetrics(ctx, broker, sample.RabbitMQ, at)
	case broker.Engine == "ACTIVEMQ" && sample.ActiveMQ != nil && sample.RabbitMQ == nil:
		return a.publishActiveMQMetrics(ctx, broker, sample.ActiveMQ, at)
	default:
		return errors.New("MQ metric snapshot does not match the broker engine")
	}
}

// Unsupported RabbitMQ queue names suppress only their series, not broker totals.
// https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/rabbitmq-logging-monitoring.html
func (a MQMetrics) publishRabbitMQMetrics(ctx context.Context, broker mq.BrokerRecord, sample *mq.RabbitMQMetrics, at time.Time) error {
	brokerDimensions := cw.Dimensions{{Name: new(cw.DimensionName("Broker")), Value: new(cw.DimensionValue(broker.Name))}}
	var ready, unacknowledged, consumers int64
	for _, queue := range sample.Queues {
		ready += queue.Ready
		unacknowledged += queue.Unacknowledged
		consumers += queue.Consumers
	}
	// Bound intermediate projection memory. Publish consumes the batch before it
	// returns; all batches still join the caller's single source transaction.
	data := make([]cw.MetricDatum, 0, min(1000, 8+4*len(sample.Queues)))
	unit := cw.StandardUnitCount
	appendGauge := func(name string, count int64, dimensions cw.Dimensions) error {
		data = append(data, cw.MetricDatum{MetricName: new(cw.MetricName(name)), Timestamp: &at, Unit: &unit, Value: new(cw.DatapointValue(count)), Dimensions: dimensions})
		if len(data) == cap(data) {
			if err := a.Metrics.Publish(ctx, "AWS/AmazonMQ", data); err != nil {
				return err
			}
			data = data[:0]
		}
		return nil
	}
	appendQueue := func(ready, unacknowledged, consumers int64, dimensions cw.Dimensions) error {
		for _, gauge := range [...]struct {
			name  string
			count int64
		}{
			{"MessageCount", ready + unacknowledged},
			{"MessageReadyCount", ready},
			{"MessageUnacknowledgedCount", unacknowledged},
			{"ConsumerCount", consumers},
		} {
			if err := appendGauge(gauge.name, gauge.count, dimensions); err != nil {
				return err
			}
		}
		return nil
	}
	for _, gauge := range [...]struct {
		name  string
		count int64
	}{
		{"ExchangeCount", sample.Exchanges},
		{"ConnectionCount", sample.Connections},
		{"ChannelCount", sample.Channels},
		{"QueueCount", int64(len(sample.Queues))},
	} {
		if err := appendGauge(gauge.name, gauge.count, brokerDimensions); err != nil {
			return err
		}
	}
	if err := appendQueue(ready, unacknowledged, consumers, brokerDimensions); err != nil {
		return err
	}
	// AWS removed Queue/VirtualHost dimensions in RabbitMQ 4.x.
	if strings.HasPrefix(broker.EngineVersion, "3.") {
		for _, queue := range sample.Queues {
			if !mqMetricDimension(queue.Name) || !mqMetricDimension(queue.VirtualHost) {
				continue
			}
			dimensions := cw.Dimensions{brokerDimensions[0],
				{Name: new(cw.DimensionName("VirtualHost")), Value: new(cw.DimensionValue(queue.VirtualHost))},
				{Name: new(cw.DimensionName("Queue")), Value: new(cw.DimensionValue(queue.Name))},
			}
			if err := appendQueue(queue.Ready, queue.Unacknowledged, queue.Consumers, dimensions); err != nil {
				return err
			}
		}
	}
	if len(data) == 0 {
		return nil
	}
	return a.Metrics.Publish(ctx, "AWS/AmazonMQ", data)
}

func mqMetricDimension(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] <= ' ' || value[i] >= 0x7f {
			return false
		}
	}
	return true
}
