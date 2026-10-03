package s3

const maxMetricsConfigurations = 1000

// RequestMetricsFilter adds request endpoint selection to the shared object
// predicate. Kind also admits access-point; no object-size predicates are admitted.
type RequestMetricsFilter struct {
	ObjectFilter
	AccessPointARN string
}

// RequestMetricsConfiguration preserves the admitted filter form. A nil filter
// includes bucket-content listings and multi-object requests as well as objects.
type RequestMetricsConfiguration struct {
	ID     string
	Filter *RequestMetricsFilter
}

type RequestMetricsReader interface {
	BucketMetricsConfiguration(BucketKey, string) (*RequestMetricsConfiguration, error)
	BucketMetricsConfigurations(BucketConfigurationQuery) ([]RequestMetricsConfiguration, error)
	BucketMetricsConfigurationCount(BucketKey) (int, error)
}

type RequestMetricsWriter interface {
	PutBucketMetricsConfiguration(BucketKey, RequestMetricsConfiguration) error
	DeleteBucketMetricsConfiguration(BucketKey, string) error
}
