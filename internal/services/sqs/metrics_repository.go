package sqs

import "time"

// MetricPublicationKey owns pending samples for one UTC minute. Queue
// identity is a dimension, not a foreign key; samples survive queue deletion.
type MetricPublicationKey struct {
	Queue  QueueKey
	Minute time.Time
}

type MetricSample struct {
	Name        string
	Value       int64
	SampleCount int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
	NextMetricQueue() (QueueRecord, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
