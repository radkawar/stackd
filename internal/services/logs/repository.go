// Package logs owns CloudWatch log groups, streams and original retained events.
package logs

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

var ErrNotFound = errors.New("CloudWatch Logs resource not found")

type Scope struct{ Partition, AccountID, Region string }
type GroupKey struct {
	Scope
	Name string
}

func (k GroupKey) ARN() string {
	return "arn:" + k.Partition + ":logs:" + k.Region + ":" + k.AccountID + ":log-group:" + k.Name
}

type GroupRecord struct {
	Key               GroupKey
	ID                string
	Created, Sequence int64
	RetentionDays     int32
	Tags              map[string]string
}
type StreamKey struct{ GroupID, Name string }
type StreamRecord struct {
	Key                                                       StreamKey
	ID                                                        string
	Created, FirstEvent, LastEvent, LastIngestion, EventCount int64
}
type EventCursor struct{ Timestamp, Ingestion, Sequence int64 }
type EventRecord struct {
	GroupID, StreamID, StreamName, ID, Message string
	EventCursor
}
type GroupQuery struct {
	Scope
	After, Prefix, Contains, Class string
	Limit                          int
}
type StreamQuery struct {
	GroupID, Prefix, After string
	AfterTime              int64
	ByTime, Descending     bool
	Limit                  int
}

// Events returns at most Limit records in traversal order. Cursor is exclusive;
// callers reverse backward pages before returning their chronological wire form.
type EventQuery struct {
	GroupID, StreamID   string
	Start, End          int64
	Cursor              EventCursor
	HasCursor, Backward bool
	Limit               int
}

type PolicyScope string

const (
	PolicyScopeAccount  PolicyScope = "ACCOUNT"
	PolicyScopeResource PolicyScope = "RESOURCE"
)

// PolicyKey identifies either a named account policy or a log-group ARN policy.
type PolicyKey struct {
	Scope
	PolicyScope PolicyScope
	Name        string
}
type PolicyRecord struct {
	Key               PolicyKey
	GroupID, Document string
	Updated, Revision int64
}
type PolicyQuery struct {
	Scope
	PolicyScope        PolicyScope
	ResourceARN, After string
	Limit              int
}

// DestinationKey identifies a logical cross-account subscription endpoint.
type DestinationKey struct {
	Scope
	Name string
}

func (k DestinationKey) ARN() string {
	return "arn:" + k.Partition + ":logs:" + k.Region + ":" + k.AccountID + ":destination:" + k.Name
}

type DestinationRecord struct {
	Key                              DestinationKey
	TargetARN, RoleARN, AccessPolicy string
	Created                          int64
	Tags                             map[string]string
}

type DestinationQuery struct {
	Scope
	Prefix, After string
	Limit         int
}

// SubscriptionKey is scoped to a log group incarnation, not its reusable name.
type SubscriptionKey struct{ GroupID, Name string }
type SubscriptionRecord struct {
	Key                                                       SubscriptionKey
	ID, Pattern, DestinationARN, Distribution, FieldSelection string
	RoleARN, TargetARN, RoleSourceARN                         string
	SenderRoleARN                                             string
	ApplyOnTransformedLogs                                    bool
	EmitSystemFields                                          []string
	Created                                                   int64
	DisabledUntil                                             time.Time
}
type SubscriptionQuery struct {
	GroupID, Prefix, After string
	Limit                  int
}

// SubscriptionDelivery retains the immutable native compressed batch. No source
// stream/event lookup is necessary after admission, including after deletion.
type SubscriptionDelivery struct {
	ID, SubscriptionID                              string
	Key                                             SubscriptionKey
	Group                                           GroupKey
	DestinationARN, ParentEventID, RequestID        string
	RoleARN, TargetARN, RoleSourceARN, PartitionKey string
	Payload                                         []byte
	Due, Expires                                    time.Time
	Version                                         uint64
	Attempts                                        int
}

// Metric filters belong to the current log-group incarnation. The single
// transformation is the native API invariant, not a generic transform engine.
type MetricFilterKey struct{ GroupID, Name string }
type MetricFilterRecord struct {
	Key                                                                MetricFilterKey
	GroupName, Pattern, MetricNamespace, MetricName, MetricValue, Unit string
	DefaultValue                                                       *float64
	Dimensions                                                         map[string]string
	ApplyOnTransformedLogs                                             bool
	EmitSystemFieldDimensions                                          []string
	FieldSelection                                                     string
	Created                                                            int64
}
type MetricFilterQuery struct {
	Scope
	GroupID, Prefix, MetricName, MetricNamespace string
	AfterName, AfterGroupName                    string
	Limit                                        int
}
type Reader interface {
	Context() context.Context
	Group(GroupKey) (GroupRecord, error)
	Groups(GroupQuery) ([]GroupRecord, error)
	Stream(StreamKey) (StreamRecord, error)
	Streams(StreamQuery) ([]StreamRecord, error)
	Events(EventQuery) ([]EventRecord, error)
	StoredBytes(groupID string, retainedAfter int64) (int64, error)
	// NextRetention returns the first physical event expiry across all scopes.
	NextRetention() (scheduler.Job, bool, error)
	ResourcePolicy(PolicyKey) (PolicyRecord, error)
	ResourcePolicies(PolicyQuery) ([]PolicyRecord, error)
	Destination(DestinationKey) (DestinationRecord, error)
	Destinations(DestinationQuery) ([]DestinationRecord, error)
	Subscription(SubscriptionKey) (SubscriptionRecord, error)
	Subscriptions(SubscriptionQuery) ([]SubscriptionRecord, error)
	SubscriptionDelivery(string) (SubscriptionDelivery, error)
	NextSubscriptionDelivery() (scheduler.Job, bool, error)
	MetricFilter(MetricFilterKey) (MetricFilterRecord, error)
	// MetricFilters is scoped and ordered by filter name, then log-group name;
	// AfterName/AfterGroupName is an exclusive continuation boundary.
	MetricFilters(MetricFilterQuery) ([]MetricFilterRecord, error)
}
type Transaction interface {
	Reader
	PutGroup(GroupRecord) error
	DeleteGroup(GroupKey) error
	PutStream(StreamRecord) error
	DeleteStream(StreamKey) error
	AppendEvent(EventRecord) error
	// ExpireEvents removes events older than each group's current retention,
	// atomically repairing the affected stream summaries.
	ExpireEvents(nowMillis int64) error
	PutResourcePolicy(PolicyRecord) error
	DeleteResourcePolicy(PolicyKey) error
	PutDestination(DestinationRecord) error
	DeleteDestination(DestinationKey) error
	PutSubscription(SubscriptionRecord) error
	DeleteSubscription(SubscriptionKey) error
	PutSubscriptionDelivery(SubscriptionDelivery) error
	DeleteSubscriptionDelivery(string) error
	PutMetricFilter(MetricFilterRecord) error
	DeleteMetricFilter(MetricFilterKey) error
}

// Repository joins the instance transaction domain. Authorization, resource
// changes and recorded management outcomes borrow the same callback context.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt rolls back a failed command without poisoning its caller's
	// transaction. Success remains provisional until that caller commits.
	Attempt(context.Context, func(Transaction) error) error
}
