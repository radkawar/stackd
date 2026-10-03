package mq

import (
	"context"
	"time"
)

// QueueMetrics is measured from one native queue, not API metadata or a local
// message ledger. Counts include only messages/consumers present when sampled.
type QueueMetrics struct {
	VirtualHost, Name                string
	Ready, Unacknowledged, Consumers int64
}

// RabbitMQMetrics contains measured broker inventories and all native queues.
// Zero counts require successful native reads, never absent data.
type RabbitMQMetrics struct {
	Exchanges, Connections, Channels int64
	Queues                           []QueueMetrics
}

// ActiveMQDestinationMetrics holds instantaneous counters from a native queue or
// topic MBean. QueueSize applies only when Kind is "Queue", never to a topic.
type ActiveMQDestinationMetrics struct {
	Name, Kind                      string
	QueueSize, Consumers, Producers int64
}

// ActiveMQMetrics contains native broker and destination gauges, not cumulative
// counters misrepresented as per-minute activity.
type ActiveMQMetrics struct {
	Connections, Consumers, Messages, Producers int64
	// Full native inventory count; the CloudWatch projection applies AWS's ceiling.
	InactiveDurableTopicSubscribers int64
	Destinations                    []ActiveMQDestinationMetrics
}

// MetricSnapshot contains exactly the variant matching the observed engine.
type MetricSnapshot struct {
	RabbitMQ *RabbitMQMetrics
	ActiveMQ *ActiveMQMetrics
}

// MetricSource performs bounded native reads outside resource transactions.
// It must reject incomplete inventory or malformed counters, never fill missing
// native fields with zero. Broker identity/ownership must be checked before I/O.
type MetricSource interface {
	ReadMetrics(context.Context, BrokerRecord) (MetricSnapshot, error)
}

// MetricPublisher joins the existing CloudWatch transaction owner. Callers fence
// the broker incarnation/version and current native identity before publishing.
// It performs no native or external I/O.
type MetricPublisher interface {
	PublishMQMetrics(context.Context, BrokerRecord, MetricSnapshot, time.Time) error
}

// TODO: Comeback implement remaining ActiveMQ gauges and calibrated per-minute
// counters, and RabbitMQ node, rate and network metrics from native observations.
// Current gauges do not establish those values or managed EC2 resource capacities.
