package elbv2

import "time"

// MetricPublicationKey retains observed request windows independently of resource
// lifetime. Publication and removal join CloudWatch in the source transaction.
type MetricPublicationKey struct {
	Scope
	LoadBalancerARN string
	Due             time.Time
}

// MetricSample is a source-owned observation, not a second CloudWatch metric
// store. TargetGroupARN and AvailabilityZone identify native dimension sets.
type MetricSample struct {
	Name, TargetGroupARN, AvailabilityZone string
	Minimum, Maximum, Sum                  float64
	Count                                  int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, bool, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
	SetNextMetricAt(Scope, string, time.Time) error
}
