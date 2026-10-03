package eventbridge

import "time"

// MetricPublicationKey owns pending samples for one scope and UTC minute.
// Bus and rule names are dimensions, not foreign keys; samples survive deletion.
type MetricPublicationKey struct {
	Scope
	Minute time.Time
}

// MetricSample retains a weighted observation. Empty dimension names mean absent
// dimensions; zero is a real observation. Callers supply finite values and counts.
type MetricSample struct {
	Name, EventBusName, RuleName, Source string
	Value                                float64
	SampleCount                          int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, bool, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
