package dynamodb

import (
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// WriteConsumers is the current incarnation's native-write projection. Plans
// refresh it under the database gate, rather than retaining queued membership.
type WriteConsumers struct {
	RecoveryID, ReplicationGroupID string
	Kinesis                        []KinesisConsumer
}

// MutationCapture owns the gap between a native write and publication to its
// retained consumers. Version orders overlapping writes across regional engines;
// it is allocated before the external effect and survives an ambiguous outcome.
// The database gate permits one outstanding capture per engine database.
type MutationCapture struct {
	Version       int64
	DatabaseID    string
	At            time.Time
	Sources       []MutationSource
	ParentEventID string
	Transactional bool
	TTL           bool
}

// MutationSource retains an incarnation independently of current control state.
// Before images serve replication conflict suppression and the destination's
// exact change envelope; each consumer applies its own no-op semantics.
type MutationSource struct {
	Table        TableKey
	PhysicalName string
	KeySchema    api.KeySchema
	WriteConsumers
	Items []MutationItem
}

type MutationItem struct {
	Key    api.Key
	Before api.AttributeMap
	// ReplicaSequence references an incoming retained change, or zero for a
	// local write. The receiver acknowledges that log entry only after the
	// expected absolute image and conflict version have actually been installed.
	ReplicaSequence int64
}

type MutationReader interface {
	ActiveWriteConsumers(TableKey, string) (WriteConsumers, error)
	MutationCapture(databaseID string) (MutationCapture, error)
}

type MutationWriter interface {
	// CreateMutationCapture allocates a monotonically increasing positive
	// version shared across regional databases. An existing capture is an error.
	CreateMutationCapture(MutationCapture) (int64, error)
	DeleteMutationCapture(databaseID string) error
}
