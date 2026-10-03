package integrations

import (
	"context"
	"fmt"
	"time"

	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/services/mq"
)

// ActiveMQ's single-instance Broker dimension includes the native instance suffix.
// All values here are instantaneous gauges; cumulative JMX counters cannot stand
// in for AWS's per-minute destination activity metrics.
// https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/activemq-logging-monitoring.html
func (a MQMetrics) publishActiveMQMetrics(ctx context.Context, broker mq.BrokerRecord, sample *mq.ActiveMQMetrics, at time.Time) error {
	brokerDimensions := cw.Dimensions{{Name: new(cw.DimensionName("Broker")), Value: new(cw.DimensionValue(broker.Name + "-1"))}}
	data := make([]cw.MetricDatum, 0, min(1000, 5+3*len(sample.Destinations)))
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
	for _, gauge := range [...]struct {
		name  string
		count int64
	}{
		{"CurrentConnectionsCount", sample.Connections},
		{"TotalConsumerCount", sample.Consumers},
		// TODO: Comeback calibrate AWS's treatment of offline durable-topic
		// backlog; upstream BrokerView excludes topic message counts.
		{"TotalMessageCount", sample.Messages},
		{"TotalProducerCount", sample.Producers},
		// AWS reports at most 2000 even when the native inventory is larger.
		{"InactiveDurableTopicSubscribersCount", min(sample.InactiveDurableTopicSubscribers, 2000)},
	} {
		if err := appendGauge(gauge.name, gauge.count, brokerDimensions); err != nil {
			return err
		}
	}
	for _, destination := range sample.Destinations {
		if destination.Kind != "Queue" && destination.Kind != "Topic" {
			return fmt.Errorf("unsupported native ActiveMQ destination kind %q", destination.Kind)
		}
		dimensions := cw.Dimensions{brokerDimensions[0], {Name: new(cw.DimensionName(destination.Kind)), Value: new(cw.DimensionValue(destination.Name))}}
		if destination.Kind == "Queue" {
			if err := appendGauge("QueueSize", destination.QueueSize, dimensions); err != nil {
				return err
			}
		}
		if err := appendGauge("ConsumerCount", destination.Consumers, dimensions); err != nil {
			return err
		}
		if err := appendGauge("ProducerCount", destination.Producers, dimensions); err != nil {
			return err
		}
	}
	if len(data) == 0 {
		return nil
	}
	return a.Metrics.Publish(ctx, "AWS/AmazonMQ", data)
}
