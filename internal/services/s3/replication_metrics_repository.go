package s3

import "time"

// ReplicationMetricKey retains the publication scope independently of bucket or
// configuration deletion. Source and destination regions have different native
// responsibilities: failure counters use the former and gauges the latter.
type ReplicationMetricKey struct {
	Source, Destination                        BucketKey
	AccountID, SourceRegion, DestinationRegion string
	RuleID                                     string
}

// ReplicationMetricPublication retains one completed minute until publication.
// Recurring rows schedule a gauge sample at At; sampling also schedules the next
// minute. Sampled rows and counters survive removal of their configuration.
// ReadyAt delays visibility without discarding observations made before RTC starts.
type ReplicationMetricPublication struct {
	Key                ReplicationMetricKey
	At                 time.Time
	ReadyAt            time.Time
	Pending            ReplicationPending
	Operations, Failed int64
	Recurring          bool
	Sampled            bool
}

// Deadline separates minute sampling from delayed CloudWatch publication.
func (publication ReplicationMetricPublication) Deadline() time.Time {
	if !publication.Recurring && publication.ReadyAt.After(publication.At) {
		return publication.ReadyAt
	}
	return publication.At
}

type ReplicationPending struct {
	Operations, Bytes int64
	Oldest            time.Time
}

type ReplicationMetricReader interface {
	NextReplicationMetricPublication() (*ReplicationMetricPublication, error)
	ReplicationMetricPublication(ReplicationMetricKey, time.Time) (*ReplicationMetricPublication, error)
	ReplicationPending(ReplicationMetricKey, time.Time) (ReplicationPending, error)
}

type ReplicationMetricWriter interface {
	// Replacement stops future sampling but preserves accepted observations.
	ReplaceReplicationMetricSchedules(BucketKey, []ReplicationMetricPublication) error
	AddReplicationMetricOutcome(key ReplicationMetricKey, at, readyAt time.Time, failed bool) error
	// Sampling retains this minute's pending aggregate and schedules the next
	// minute atomically. Completion only consumes a published observation.
	SampleReplicationMetricPublication(ReplicationMetricPublication) error
	CompleteReplicationMetricPublication(ReplicationMetricPublication) error
}
