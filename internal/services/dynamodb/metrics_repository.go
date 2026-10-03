package dynamodb

import "time"

// MetricPublicationKey owns samples for one UTC minute. The resource identity
// is a CloudWatch dimension, not a foreign key: samples survive table deletion.
type MetricPublicationKey struct {
	Table  TableKey
	Minute time.Time
}

// MetricSample retains the observed distribution, including fractional read
// units. An empty IndexName identifies the table, not the sum of its indexes.
// Operation is populated only for operation-dimensioned series.
// OperationType and Verb retain AWS's PartiQL-specific metric dimensions.
type MetricSample struct {
	IndexName     string
	Operation     string
	OperationType string
	Verb          string
	Name          string
	Value         float64
	SampleCount   int64
}

type MetricReader interface {
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
	// NextMetricTable selects an ACTIVE or UPDATING table across all scopes in
	// deadline and table-key order. Zero deadlines initialize recurring work.
	NextMetricTable() (TableRecord, error)
}

type MetricWriter interface {
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
