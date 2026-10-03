package dynamodb

import (
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// RecoveryRecord owns a continuous-backup interval and its private native
// baseline. TableRecord.RecoveryID is the authoritative enabled interval; older
// intervals remain only while an admitted restore still needs them.
// SnapshotAt is nil until the baseline has actually been copied. CompactThrough
// retains an interrupted native fold, whose source changes cannot yet be removed.
type RecoveryRecord struct {
	ID                                           string
	Table                                        TableKey
	DatabaseID, SourcePhysicalName, PhysicalName string
	KeySchema                                    api.KeySchema
	AttributeDefinitions                         api.AttributeDefinitions
	RecoveryPeriodInDays                         int
	EarliestAt                                   time.Time
	SnapshotAt, CompactThrough                   *time.Time
}

// RecoveryChange is an accepted item image, not an expression to execute again.
// A nil Item removes Key. Sequence preserves write order at equal service times.
type RecoveryChange struct {
	RecoveryID string
	Sequence   int64
	At         time.Time
	Key        api.Key
	Item       api.AttributeMap
}

type RecoveryChangeQuery struct {
	RecoveryID string
	After      int64
	// ThroughSequence pins an admitted restore against later writes at the
	// same service instant. Nil leaves the sequence upper bound unrestricted.
	ThroughSequence *int64
	Through         time.Time
	Limit           int
}

type RecoveryReader interface {
	Recovery(id string) (RecoveryRecord, error)
	// RecoverySequence returns the highest retained sequence, zero if empty.
	RecoverySequence(id string) (int64, error)
	// Recoveries returns ID order, optionally restricted to one database.
	Recoveries(databaseID string) ([]RecoveryRecord, error)
	// UnsettledRecoveries limits mutation preparation to baselines or folds
	// whose native effects must finish before another write or restore.
	UnsettledRecoveries(databaseID string) ([]RecoveryRecord, error)
	// RecoveryChanges returns sequence order after After, through the inclusive
	// service-time bound. A zero bound or nonpositive limit is unrestricted.
	RecoveryChanges(RecoveryChangeQuery) ([]RecoveryChange, error)
}

type RecoveryWriter interface {
	PutRecovery(RecoveryRecord) error
	// DeleteRecovery also removes its retained changes.
	DeleteRecovery(id string) error
	// AppendRecoveryChanges assigns monotonically increasing positive sequences
	// in input order. Caller-owned Sequence fields are not persisted.
	AppendRecoveryChanges([]RecoveryChange) error
	DeleteRecoveryChanges(id string, through time.Time) error
}
