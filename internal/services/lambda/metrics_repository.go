package lambda

import (
	"context"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
)

// MetricPublisher joins native service samples to the instance transaction. These
// are not customer PutMetricData requests and do not use customer permissions.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

// MetricPublicationKey owns pending samples for a completed UTC minute. Resource
// identities are dimensions, not foreign keys; statistics survive their deletion.
type MetricPublicationKey struct {
	Function FunctionKey
	Minute   time.Time
	// Resource and ExecutedVersion are native CloudWatch dimensions. Empty
	// Resource identifies the function-wide aggregate, not an implicit version.
	Resource, ExecutedVersion string
	// EventSourceMappingUUID selects source-only dimensions. Function carries
	// the scope, with its name and both function dimensions empty.
	EventSourceMappingUUID string
}

type MetricSample struct {
	Name        string
	Value       float64
	SampleCount int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
