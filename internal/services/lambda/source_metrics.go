package lambda

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"
)

const (
	metricSourcePolled   = "PolledEventCount"
	metricSourceFiltered = "FilteredOutEventCount"
	metricSourceInvoked  = "InvokedEventCount"
	metricSourceFailed   = "FailedInvokeEventCount"
	metricSQSDeleted     = "DeletedEventCount"
)

// Source counters describe polling and delivery, not fabricated function errors.
func (s *Service) sourceMetric(mapping EventSourceMappingRecord, name string, count int) {
	if !s.sourceMetricEnabled(mapping, name) {
		return
	}
	now := s.clock.Now()
	err := s.repository.Update(s.lifetime, func(tx Transaction) error {
		return stageSourceMetrics(tx, mapping, now, MetricSample{Name: name, Value: float64(count), SampleCount: 1})
	})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("Lambda source metric retention failed", "mapping", mapping.Key.ARN(), "error", err)
		}
		return
	}
	s.jobs.Wake()
}

func (s *Service) sourceMetricEnabled(mapping EventSourceMappingRecord, name string) bool {
	return s.metrics != nil && (name == "ProvisionedPollers" || slices.Contains(mapping.Settings.Metrics, "EventCount"))
}

// Callers select enabled metrics before opening or joining their transaction.
func stageSourceMetrics(tx Transaction, mapping EventSourceMappingRecord, at time.Time, samples ...MetricSample) error {
	key := MetricPublicationKey{Function: FunctionKey{Scope: mapping.Key.Scope}, Minute: at.UTC().Truncate(time.Minute), EventSourceMappingUUID: mapping.Key.UUID}
	return tx.AddMetricSamples(key, samples)
}
