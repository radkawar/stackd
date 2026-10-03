// Package dynamodb owns DynamoDB control state and authorization. Item storage
// and expression execution belong to the injected external engine.
package dynamodb

import (
	"context"
	"errors"
	"time"

	engine "stackd/engine/dynamodb"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/dynamodb"
)

var ErrNotFound = errors.New("DynamoDB resource not found")

type Scope struct{ Partition, AccountID, Region string }
type TableKey struct {
	Scope
	Name string
}

func (k TableKey) ARN() string {
	return "arn:" + k.Partition + ":dynamodb:" + k.Region + ":" + k.AccountID + ":table/" + k.Name
}

// DatabaseRecord retains the engine identity independently of table names and
// rotating caller credentials. Retiring databases cannot receive new tables.
// Only one nonretiring database exists in each partition/account/region.
type DatabaseRecord struct {
	Spec     engine.Specification
	Retiring bool
}

// TableRecord owns generated public metadata. PhysicalName is an opaque,
// case-safe engine identifier, never a customer-visible table name. Pending
// inputs exist only until their actual engine transition has been observed.
// Current tags and resource policies have their own records.
type TableRecord struct {
	Key           TableKey
	Data          api.TableDescription
	DatabaseID    string
	PhysicalName  string
	PendingCreate *api.CreateTableInput
	PendingUpdate *api.UpdateTableInput
	// UpdateAcceptedAt dates provisional metadata while Data keeps the last
	// settled throughput history. It is present only with PendingUpdate.
	UpdateAcceptedAt time.Time
	TTL              api.TimeToLiveDescription
	TTLChangedAt     time.Time
	TTLNextScan      time.Time
	// MetricsNextAt is the next completed-minute sampling deadline. Zero
	// means that initial gauges have not yet been sampled.
	MetricsNextAt time.Time
	// RecoveryID selects the enabled continuous-backup interval.
	RecoveryID string
	// RestoreRecoveryID pins historical data until RestoreSummary is completed.
	RestoreRecoveryID       string
	RestoreRecoverySequence int64
	Replica                 ReplicaState
	KinesisConsumers        []KinesisConsumer
}

// TTLDeletion owns one conditional expiry attempt until its native stream effect
// is captured. Database serialization permits at most one pending attempt.
type TTLDeletion struct {
	Table                    TableKey
	DatabaseID, PhysicalName string
	StreamARN, NativeARN     string
	Key                      api.Key
	Attribute                api.AttributeName
	Expiry                   string
	CreatedAt                time.Time
}

type TableQuery struct {
	Scope
	After string
	Limit int
}

type TagRecord struct {
	Key  TableKey
	Tags api.TagList
}

type PolicyKey struct {
	Scope
	ResourceARN string
}

type PolicyRecord struct {
	Key      PolicyKey
	Policy   authorization.BoundPolicy
	Revision string
}

// Repository joins the shared transaction domain through callback contexts.
// No engine call may run while one of these callbacks holds the transaction.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	KinesisReader
	BackupReader
	RecoveryReader
	MutationReader
	ReplicaReader
	MetricReader
	TransactionCapacityReader
	Context() context.Context
	Database(Scope) (DatabaseRecord, error)
	Databases() ([]DatabaseRecord, error)
	Table(TableKey) (TableRecord, error)
	Tables(TableQuery) ([]TableRecord, error)
	// OnDemandSwitches returns the last four entries into on-demand mode,
	// oldest first. Creation counts; requests leaving the mode unchanged do not.
	OnDemandSwitches(TableKey) ([]time.Time, error)
	// PendingTables returns CREATING, UPDATING and DELETING tables across all
	// scopes in partition/account/region/name order.
	PendingTables() ([]TableRecord, error)
	// TTLTables returns enabled, writable tables in next-scan and scope order.
	TTLTables() ([]TableRecord, error)
	TTLDeletion(databaseID string) (TTLDeletion, error)
	Tags(TableKey) (TagRecord, error)
	Policy(PolicyKey) (PolicyRecord, error)
	Stream(PolicyKey) (StreamGeneration, error)
	Streams() ([]StreamGeneration, error)
	StreamShards(streamARN string) ([]StreamShard, error)
	StreamEntries(StreamEntryQuery) ([]StreamEntry, error)
}

type Transaction interface {
	Reader
	KinesisWriter
	BackupWriter
	RecoveryWriter
	MutationWriter
	ReplicaWriter
	MetricWriter
	TransactionCapacityWriter
	PutDatabase(DatabaseRecord) error
	DeleteDatabase(id string) error
	PutTable(TableRecord) error
	PutOnDemandSwitches(TableKey, []time.Time) error
	// DeleteTable removes the table and its tags, not retained stream history.
	DeleteTable(TableKey) error
	PutTTLDeletion(TTLDeletion) error
	DeleteTTLDeletion(databaseID string) error
	PutTags(TagRecord) error
	PutPolicy(PolicyRecord) error
	DeletePolicy(PolicyKey) error
	PutStream(StreamGeneration) error
	DeleteStream(PolicyKey) error
	PutStreamShard(StreamShard) error
	PutStreamEntry(StreamEntry) error
	// TrimStreamEntries atomically advances trim points and deletes expired
	// records, returning the oldest retained creation time (zero if empty).
	TrimStreamEntries(streamARN string, cutoff time.Time) (time.Time, error)
}
