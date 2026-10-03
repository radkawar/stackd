package xray

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
)

var ErrNotFound = errors.New("X-Ray resource not found")

// Scope isolates traces and resource policies by their regional owner.
type Scope struct {
	Partition string
	AccountID string
	Region    string
}

type TraceKey struct {
	Scope
	ID string
}

type SegmentKey struct {
	TraceKey
	ID string
}

// SegmentRecord retains the native segment document, not a resource-state blob.
// Indexed fields own assembly and completion transitions; Document preserves
// customer annotations and metadata. Inline subsegments have their own records.
type SegmentRecord struct {
	Key         SegmentKey
	ParentID    string
	Subsegment  bool
	InlineOrder int64 // Zero for independent submissions, otherwise sibling order.
	Start       float64
	End         *float64
	InProgress  bool
	Document    string
	Received    time.Time
	// Completed is the first completed admission, which owns graph aggregation.
	// Received remains the original admission used by document retention.
	Completed *time.Time
	// Revisions preserve command ordering even when virtual time is unchanged.
	// A completed document freezes at Revision; ReceivedRevision is its admission.
	ReceivedRevision int64
	Revision         int64
}

type PolicyKey struct {
	Scope
	Name string
}

type PolicyRecord struct {
	Key      PolicyKey
	Policy   authorization.BoundPolicy
	Revision int64
	Updated  time.Time
}

// Repository joins trace writes and API events in the configured transaction
// domain. Callbacks must not perform network or other external effects.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Segment(SegmentKey) (SegmentRecord, error)
	TraceSegments(TraceKey) ([]SegmentRecord, error)
	EarliestSegmentReceipt() (time.Time, bool, error)
	Trace(TraceKey) (TraceRecord, error)
	Traces(TraceSelection) ([]TraceData, error)
	Group(GroupKey) (GroupRecord, error)
	Groups(Scope) ([]GroupRecord, error)
	NextGroupMetric() (GroupMetricRecord, error)
	ResourcePolicies(Scope) ([]PolicyRecord, error)
	SamplingRule(SamplingRuleKey) (SamplingRuleRecord, error)
	SamplingRules(Scope) ([]SamplingRuleRecord, error)
	SamplingClients(SamplingRuleKey) ([]SamplingClientRecord, error)
	SamplingStatistics(SamplingRuleKey) ([]SamplingStatisticRecord, error)
	SamplingBoostStatistics(SamplingRuleKey) ([]SamplingBoostStatisticRecord, error)
	SamplingBoost(SamplingRuleKey) (SamplingBoostRecord, error)
	// SamplingModified returns the Unix epoch before any rule configuration change.
	SamplingModified(Scope) (time.Time, error)
	EarliestSamplingReceipt() (time.Time, bool, error)
}

type Transaction interface {
	Reader
	PutSegment(SegmentRecord) error
	DeleteExpiredSegments(time.Time) error
	PutTrace(TraceRecord) error
	PutGroup(GroupRecord) error
	// AddGroupTrace retains the first matching membership and reports insertion.
	AddGroupTrace(GroupKey, TraceKey, GroupMembership) (bool, error)
	DeleteGroup(GroupKey) error
	AddGroupMetric(GroupMetricKey) error
	DeleteGroupMetric(GroupMetricKey) error
	PutResourcePolicy(PolicyRecord) error
	DeleteResourcePolicy(PolicyKey) error
	PutSamplingRule(SamplingRuleRecord) error
	DeleteSamplingRule(SamplingRuleKey) error
	PutSamplingStatistic(SamplingStatisticRecord) error
	PutSamplingClient(SamplingClientRecord) error
	PutSamplingBoostStatistic(SamplingBoostStatisticRecord) error
	PutSamplingBoost(SamplingBoostRecord) error
	SetSamplingModified(Scope, time.Time) error
	DeleteExpiredSamplingState(time.Time) error
}
