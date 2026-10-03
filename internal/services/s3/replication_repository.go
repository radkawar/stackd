package s3

import "time"

// ReplicationConfiguration contains admitted bucket rules. Accepted object work
// retains its destination and role independently of later configuration changes.
type ReplicationConfiguration struct {
	RoleARN string
	Rules   []ReplicationRule
}

// ReplicationFilter preserves the native filter form as well as its predicate.
// Kind is legacy, empty, prefix, tag or and. Prefix distinguishes omission from
// an explicit empty prefix inside an And filter; Tags retain their input order.
type ReplicationFilter struct {
	Kind   string
	Prefix *string
	Tags   []Tag
}

type ReplicationRule struct {
	ID                      string
	Priority                *int32
	Enabled                 bool
	Filter                  ReplicationFilter
	DeleteMarkerReplication string
	SSEKMSObjects           string
	ReplicaModifications    string
	Destination             ReplicationDestination
}

// ReplicationDestination retains accepted optional controls. Empty StorageClass
// means inherit the source class; explicit STANDARD must remain distinguishable.
// Empty status members mean the corresponding optional block was not supplied.
// AccountID is the submitted assertion, not a verified destination owner.
// Region is the destination location verified at configuration admission.
type ReplicationDestination struct {
	Bucket         BucketKey
	Region         string
	AccountID      string
	OwnerOverride  bool
	StorageClass   string
	KMSKeyID       string
	MetricsStatus  string
	MetricsMinutes *int32
	// MetricsReadyAt delays RTC publication, not minute sampling. Accepted
	// jobs retain the activation deadline when configuration is replaced.
	MetricsReadyAt time.Time
	TimeStatus     string
	TimeMinutes    *int32
}

// ReplicationOperation is the independently authorized work carried by a source
// mutation. Object delivery may succeed while its tag projection fails.
type ReplicationOperation string

const (
	ReplicationObject    ReplicationOperation = "OBJECT_PUT"
	ReplicationDelete    ReplicationOperation = "DELETE_MARKER"
	ReplicationTags      ReplicationOperation = "TAGGING_PUT"
	ReplicationACL       ReplicationOperation = "ACL_PUT"
	ReplicationRetention ReplicationOperation = "RETENTION_PUT"
	ReplicationLegalHold ReplicationOperation = "LEGAL_HOLD_PUT"
)

// ReplicationState identifies the latest accepted attempt for one destination
// and independently mutable component. Sequence fences an older completion from
// overwriting the outcome of a newer accepted mutation.
type ReplicationState struct {
	Source      ObjectVersionKey
	Destination BucketKey
	Operation   ReplicationOperation
	Sequence    int64
	Status      string
}

// ReplicationJob retains accepted work, not configuration or plaintext copies.
// Sequence is allocated by the existing S3 transaction sequencer on insertion;
// retries retain it. Source version removal removes its remaining work.
type ReplicationJob struct {
	Sequence      int64
	Source        ObjectVersionKey
	Destination   ReplicationDestination
	Operation     ReplicationOperation
	RoleARN       string
	RuleID        string
	ParentEventID string
	Created       time.Time
	Due           time.Time
	Attempts      int
	// ThresholdReported records the one RTC threshold notification, including
	// across restart while transient failures leave delivery pending.
	ThresholdReported bool
}

// Deadline is the next delivery attempt or the outstanding RTC notification.
func (job ReplicationJob) Deadline() time.Time {
	if job.Destination.TimeStatus == "Enabled" && !job.ThresholdReported {
		threshold := job.Created.Add(15 * time.Minute)
		if threshold.Before(job.Due) {
			return threshold
		}
	}
	return job.Due
}
