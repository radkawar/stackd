package s3

// AnalyticsConfiguration retains the admitted storage-class analysis selection.
// The only modeled export format and schema are CSV and V_1; admission owns them.
type AnalyticsConfiguration struct {
	ID          string
	Filter      *ObjectFilter
	Destination *AnalyticsDestination
}

// AnalyticsDestination is a reference, not a preflighted destination. Optional
// account and prefix fields preserve absence independently of their contents.
type AnalyticsDestination struct {
	BucketARN string
	AccountID *string
	Prefix    *string
}

type AnalyticsReader interface {
	BucketAnalyticsConfiguration(BucketKey, string) (*AnalyticsConfiguration, error)
	BucketAnalyticsConfigurations(BucketConfigurationQuery) ([]AnalyticsConfiguration, error)
	BucketAnalyticsConfigurationCount(BucketKey) (int, error)
}

type AnalyticsWriter interface {
	PutBucketAnalyticsConfiguration(BucketKey, AnalyticsConfiguration) error
	DeleteBucketAnalyticsConfiguration(BucketKey, string) error
}
