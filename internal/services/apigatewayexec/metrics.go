package apigatewayexec

import (
	"context"
	"time"
)

// MetricSample retains observed values and their multiplicity. Zero-valued error
// samples are significant: Average must use all contributing requests.
type MetricSample struct {
	Name        string
	Value       float64
	SampleCount int64
}

// Metrics records execution samples under the resolved API owner's scope. The
// implementation owns retained publication and the native CloudWatch dimensions;
// execution code owns which completed work contributes each sample.
type Metrics interface {
	RecordMetrics(context.Context, *Route, time.Time, []MetricSample) error
}
