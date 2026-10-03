package ecs

import "time"

// MetricPublicationKey groups completed windows independently of service lifetime.
// Deleting a service must not discard its already-observed utilization.
type MetricPublicationKey struct {
	ServiceKey
	Due time.Time
}

// MetricSample retains one task's observations within a publication window.
// Native ECS publishes one CloudWatch sample per contributing task, not one per
// twenty-second observation. The empty TaskID belongs to LiveTaskCount.
type MetricSample struct {
	Name, TaskID          string
	Resolution            int32
	Minimum, Maximum, Sum float64
	Count                 int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, bool, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
