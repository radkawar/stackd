package s3

import "time"

// InventoryConfiguration retains an admitted definition and its next report.
// OptionalFields preserves order, duplicates and absent versus empty lists.
// Destination references are checked for syntax at admission, not existence.
type InventoryConfiguration struct {
	ID             string
	Enabled        bool
	AllVersions    bool
	Weekly         bool
	FilterPrefix   *string
	OptionalFields []string
	Destination    InventoryDestination
	ParentEventID  string
	NextReport     time.Time
}

type InventoryDestination struct {
	BucketARN string
	AccountID *string
	Prefix    *string
	Format    string
	// Empty inherits the destination default; otherwise AES256 or aws:kms.
	Encryption string
	KMSKeyID   string
}

type InventoryReader interface {
	BucketInventoryConfiguration(BucketKey, string) (*InventoryConfiguration, error)
	BucketInventoryConfigurations(BucketConfigurationQuery) ([]InventoryConfiguration, error)
	BucketInventoryConfigurationCount(BucketKey) (int, error)
	// NextInventoryConfiguration selects enabled work by deadline, then bucket
	// and configuration ID. A nil configuration means no scheduled report.
	NextInventoryConfiguration() (BucketKey, *InventoryConfiguration, error)
}

type InventoryWriter interface {
	PutBucketInventoryConfiguration(BucketKey, InventoryConfiguration) error
	DeleteBucketInventoryConfiguration(BucketKey, string) error
	// AdvanceInventoryReport acknowledges only the selected configuration
	// revision and deadline. Replacement or deletion makes it a no-op.
	AdvanceInventoryReport(bucket BucketKey, id, parentEventID string, previous, next time.Time) error
}
