package s3

import "time"

// LifecycleConfiguration owns admitted rules and the next daily evaluation.
// Replacing or deleting it changes subsequent evaluations, not object metadata.
// ParentEventID links system notifications to the configuration command without
// inventing public API calls for lifecycle's internal mutations.
type LifecycleConfiguration struct {
	Rules             []LifecycleRule
	MinimumObjectSize string
	NextScan          *time.Time
	ParentEventID     string
}

type LifecycleRule struct {
	ID                    string
	Enabled               bool
	Filter                ObjectFilter
	Expiration            *LifecycleExpiration
	Transitions           []LifecycleTransition
	NoncurrentExpiration  *LifecycleNoncurrentExpiration
	NoncurrentTransitions []LifecycleNoncurrentTransition
	AbortIncompleteDays   *int32
}

// LifecycleWhen is either an absolute midnight UTC or an age in calendar days.
// Admission ensures exactly one is present for timed actions. Expired-marker
// cleanup uses neither: it depends on the remaining version history instead.
type LifecycleWhen struct {
	Date *time.Time
	Days *int32
}

type LifecycleExpiration struct {
	LifecycleWhen
	ExpiredObjectDeleteMarker *bool
}

type LifecycleTransition struct {
	LifecycleWhen
	StorageClass string
}

type LifecycleNoncurrentExpiration struct {
	Days                    int32
	NewerNoncurrentVersions *int32
}

type LifecycleNoncurrentTransition struct {
	LifecycleNoncurrentExpiration
	StorageClass string
}

// BucketScan identifies a bucket's next evaluation. The deadline also fences
// a stale selection after configuration replacement or an earlier run.
type BucketScan struct {
	Bucket BucketKey
	Due    time.Time
}
