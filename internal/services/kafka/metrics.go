package kafka

import (
	"context"
	"errors"
	"math"
	"time"
)

// BrokerMetric is measured from the real broker. Timestamp is set from the
// service clock after collection. No zero is supplied for an absent counter.
type BrokerMetric struct {
	BrokerID   int32
	Name, Unit string
	Value      float64
	Timestamp  time.Time
}

type Metrics interface {
	PublishKafkaMetrics(context.Context, Scope, string, []BrokerMetric) error
}

type MetricsRuntime interface {
	ReadMetrics(context.Context, Specification) ([]BrokerMetric, error)
}

func (s *Service) collectMetrics(ctx context.Context, cluster ClusterRecord, spec Specification) error {
	if !cluster.DefaultMetrics {
		return nil
	}
	runtime, ok := s.runtime.(MetricsRuntime)
	if !ok || s.metrics == nil {
		return errors.New("native Kafka DEFAULT monitoring is unavailable")
	}
	metrics, err := runtime.ReadMetrics(ctx, spec)
	if err != nil {
		return err
	}
	if len(metrics) == 0 {
		return errors.New("native Kafka DEFAULT monitoring returned no measurements")
	}
	at := s.clock.Now()
	for index := range metrics {
		metric := &metrics[index]
		if metric.BrokerID < 1 || metric.BrokerID > cluster.Brokers || metric.Name == "" || metric.Unit == "" || math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) {
			return errors.New("native Kafka monitoring returned an invalid measurement")
		}
		metric.Timestamp = at
	}
	return s.metrics.PublishKafkaMetrics(ctx, cluster.Scope, cluster.Name, metrics)
}
