package s3

import "time"

// AccessTier identifies an asynchronous Intelligent-Tiering archive tier.
// The empty value is immediately readable; billing-only subtiers are not state.
type AccessTier string

const (
	ArchiveAccessTier     AccessTier = "ARCHIVE_ACCESS"
	DeepArchiveAccessTier AccessTier = "DEEP_ARCHIVE_ACCESS"
)

// ObjectTiering belongs to eligible Intelligent-Tiering version metadata, not
// its immutable payload. Reads update Accessed without changing LastModified.
type ObjectTiering struct {
	Accessed    time.Time
	ArchiveTier AccessTier
}

type TieringRule struct {
	AccessTier AccessTier
	Days       int32
}

// TieringConfiguration retains the admitted filter form and tier ordering.
// A nil filter matches the entire bucket; empty filters are not admitted.
type TieringConfiguration struct {
	ID            string
	Enabled       bool
	Filter        *ObjectFilter
	Tierings      []TieringRule
	ParentEventID string
}

type TieringReader interface {
	BucketTieringConfiguration(BucketKey, string) (*TieringConfiguration, error)
	BucketTieringConfigurations(BucketConfigurationQuery) ([]TieringConfiguration, error)
	BucketTieringConfigurationCount(BucketKey) (int, error)
	BucketHasEnabledTiering(BucketKey) (bool, error)
	NextTieringScan() (*BucketScan, error)
}

type TieringWriter interface {
	PutBucketTieringConfiguration(BucketKey, TieringConfiguration) error
	DeleteBucketTieringConfiguration(BucketKey, string) error
	// A nil deadline removes the bucket's scheduled scan.
	SetTieringScan(BucketKey, *time.Time) error
	// A nil state clears tiering after a storage-class transition. Non-nil
	// updates require the same CreatedOrder and Intelligent-Tiering class, so a
	// detached read cannot retier a replacement or lifecycle-moved version.
	// An absent or changed version is a successful no-op, never resurrected.
	SetObjectTiering(ObjectVersionKey, int64, *ObjectTiering) error
}
