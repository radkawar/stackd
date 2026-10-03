package lambda

import (
	"context"
	"net/http"
	"time"
)

const metricURLLatency = "UrlRequestLatency"

func (s *Service) recordFunctionURLMetrics(ctx context.Context, ref FunctionReference, at time.Time, elapsed time.Duration, status int, executedVersion string, functionError bool) error {
	if s.metrics == nil {
		return nil
	}
	values := [4]MetricSample{
		{Name: "UrlRequestCount", Value: 1, SampleCount: 1},
		{Name: metricURLLatency, Value: float64(elapsed) / float64(time.Millisecond), SampleCount: 1},
	}
	samples := values[:2]
	if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
		values[2] = MetricSample{Name: "Url4xxCount", Value: 1, SampleCount: 1}
		samples = values[:3]
	}
	// The isolated native throw returned HTTP 502 and Errors=1, but no Url5xxCount
	// datum. A function-provided HTTP 500 did publish that counter.
	if status >= http.StatusInternalServerError && !functionError {
		values[2] = MetricSample{Name: "Url5xxCount", Value: 1, SampleCount: 1}
		samples = values[:3]
	}
	if executedVersion == "" {
		// URL front-door responses have no execution metric batch. Native CORS
		// interception and rejected credentials still publish an Errors=0 sample.
		samples = append(samples, MetricSample{Name: "Errors", SampleCount: 1})
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return s.stageMetricSamples(tx, ref, executedVersion, at, samples)
	}); err != nil {
		return err
	}
	s.jobs.Wake()
	return nil
}
