// Package kinesis owns Kinesis control state, authorization and record routing.
// Record bytes are stored only by the injected external log engine.
package kinesis

import (
	"context"
	"errors"
	"fmt"
	"time"

	engine "stackd/engine/kinesis"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/kinesis"
)

var ErrNotFound = errors.New("kinesis resource not found")

type Scope struct{ Partition, AccountID, Region string }

type StreamKey struct {
	Scope
	Name string
}

func (k StreamKey) ARN() string {
	return "arn:" + k.Partition + ":kinesis:" + k.Region + ":" + k.AccountID + ":stream/" + k.Name
}

// StreamRecord retains one incarnation and the last settled public metadata.
// Pending changes remain separate until reconciliation has observed the native
// log. NextPartition allocates physical partitions without reusing closed shards.
type StreamRecord struct {
	Key             StreamKey
	Owner           ResourceOwner
	EngineID        string
	Data            api.StreamDescriptionSummary
	Pending         *StreamUpdate
	NextPartition   int32
	RetentionNextAt time.Time
	// Uniform scaling has its own per-incarnation daily admission window.
	ShardCountUpdates []time.Time
	EncryptionUpdates []EncryptionUpdate
}

func (s StreamRecord) Specification() engine.Specification {
	return engine.Specification{ID: s.EngineID, Partition: s.Key.Partition, AccountID: s.Key.AccountID, Region: s.Key.Region}
}

type EncryptionUpdate struct {
	At      time.Time
	Enabled bool
}

// StreamUpdate is a pending delta, not a second copy of resource identity.
// Zero scalar values mean unchanged. A nonnil Monitoring slice can be empty to
// disable all enhanced metrics. Resharding also owns Opening ShardRecords.
type StreamUpdate struct {
	AcceptedAt       time.Time
	RetentionHours   int32
	Mode             api.StreamMode
	MaxRecordSizeKiB int32
	EncryptionType   api.EncryptionType
	KeyID            string
	Monitoring       []api.MetricsName
	WarmMiBps        *int32
	// PeakShardCount reserves the transient capacity required by a reshard.
	PeakShardCount int32
}

type StreamQuery struct {
	Scope
	After string
	Limit int
}

type ShardKey struct {
	Stream    StreamKey
	Partition int32
}

func (k ShardKey) ID() string { return fmt.Sprintf("shardId-%012d", k.Partition) }

type ShardState string

const (
	ShardOpening ShardState = "OPENING"
	ShardOpen    ShardState = "OPEN"
	ShardClosed  ShardState = "CLOSED"
)

// ShardRecord maps an AWS shard to its native partition. Opening children name
// their parents in Data; reconciliation closes those parents atomically with
// publishing the children. ClosedAt dates the retained historical topology.
type ShardRecord struct {
	Key      ShardKey
	Data     api.Shard
	State    ShardState
	OpenedAt time.Time
	ClosedAt time.Time
}

type ConsumerKey struct {
	Stream    StreamKey
	Name      string
	CreatedAt int64
}

func (k ConsumerKey) ARN() string {
	return fmt.Sprintf("%s/consumer/%s:%d", k.Stream.ARN(), k.Name, k.CreatedAt)
}

type ConsumerRecord struct {
	Key   ConsumerKey
	Owner ResourceOwner
	Data  api.ConsumerDescription
	// DeleteAt retains the asynchronous deregistration deadline.
	DeleteAt time.Time
}

// ResourceKey identifies either a stream or one registered consumer. Tags and
// policies apply to that exact ARN, not implicitly to its parent or children.
type ResourceKey struct {
	Scope
	ARN string
}

type TagRecord struct {
	Key  ResourceKey
	Tags api.TagList
}

// PolicyRecord separates immediately readable policy state from its previously
// effective binding during the service-clock propagation interval. An empty
// Policy.Document means deletion; Effective may still deny until PublishAt.
type PolicyRecord struct {
	Key       ResourceKey
	Owner     ResourceOwner
	Policy    authorization.BoundPolicy
	Effective authorization.BoundPolicy
	PublishAt time.Time
}

type AccountRecord struct {
	Scope
	Commitment api.MinimumThroughputBillingCommitmentOutput
}

// Metric publications survive stream deletion; their resource key identifies
// CloudWatch dimensions rather than a foreign-key relationship.
type MetricPublicationKey struct {
	Stream StreamKey
	Minute time.Time
}

type MetricSample struct {
	ShardID      string
	ConsumerName string
	Name         string
	Value        float64
	SampleCount  int64
}

// Repository joins the shared transaction domain through callback contexts.
// Native engine calls must happen outside these callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Stream(StreamKey) (StreamRecord, error)
	Streams(StreamQuery) ([]StreamRecord, error)
	// AllStreams returns every incarnation in scope/name order for recovery
	// and service-clock reconciliation.
	AllStreams() ([]StreamRecord, error)
	Shards(StreamKey) ([]ShardRecord, error)
	Consumer(ConsumerKey) (ConsumerRecord, error)
	Consumers(StreamKey) ([]ConsumerRecord, error)
	Tags(ResourceKey) (TagRecord, error)
	Policy(ResourceKey) (PolicyRecord, error)
	Account(Scope) (AccountRecord, error)
	// ModeSwitches survive deletion/recreation of the same stream ARN.
	ModeSwitches(StreamKey) ([]time.Time, error)
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type Transaction interface {
	Reader
	PutStream(StreamRecord) error
	// DeleteStream removes its shards, consumers, tags and policies. It does
	// not remove mode-switch admission history or pending metric publications.
	DeleteStream(StreamKey) error
	PutShard(ShardRecord) error
	PutConsumer(ConsumerRecord) error
	DeleteConsumer(ConsumerKey) error
	PutTags(TagRecord) error
	PutPolicy(PolicyRecord) error
	DeletePolicy(ResourceKey) error
	PutAccount(AccountRecord) error
	PutModeSwitches(StreamKey, []time.Time) error
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}
