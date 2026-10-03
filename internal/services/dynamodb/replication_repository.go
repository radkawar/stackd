package dynamodb

import (
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// ReplicaState is this table incarnation's membership in a version-2019 MREC
// group. Public peer descriptions are derived from the other current members,
// not retained as competing copies in each TableDescription.
type ReplicaState struct {
	GroupID string
	// Cursor acknowledges append order. Item versions independently resolve
	// writes whose native outcome was published after a later regional write.
	Cursor         int64
	LastSourceAt   time.Time
	UnauthorizedAt *time.Time
	// SettingsPending distinguishes service-owned regional propagation from a
	// caller's local PendingUpdate. The controller authorizes it as the SLR.
	SettingsPending bool
}

// ReplicaBootstrap owns a private immutable source snapshot until a new member
// has copied its contents and the accompanying per-item conflict versions.
// Cursor pins the source's consumed log position at snapshot creation. Later
// changes are applied normally, including changes published late by other regions.
type ReplicaBootstrap struct {
	Table                                TableKey
	Source                               TableKey
	SourceDatabaseID, SourcePhysicalName string
	SnapshotPhysicalName                 string
	KeySchema                            api.KeySchema
	AttributeDefinitions                 api.AttributeDefinitions
	Ready, Copied                        bool
	Cursor                               int64
}

// ReplicaChange retains accepted postimages, never customer expressions. A nil
// Item deletes Key. Sequence is publication order; Version is the original
// native-write ordering point, including after response loss and recovery.
type ReplicaChange struct {
	GroupID            string
	Sequence, Version  int64
	At                 time.Time
	Origin             TableKey
	OriginPhysicalName string
	KeyID              string
	Key                api.Key
	Item               api.AttributeMap
}

type ReplicaReader interface {
	// ReplicaTables returns scope/name order. Empty groupID selects all members.
	ReplicaTables(groupID string) ([]TableRecord, error)
	ReplicaBootstrap(TableKey) (ReplicaBootstrap, error)
	// ReplicaBootstraps selects snapshots owned by a source database; an empty
	// databaseID selects all. Records are returned in target scope/name order.
	ReplicaBootstraps(databaseID string) ([]ReplicaBootstrap, error)
	ReplicaSequence(groupID string) (int64, error)
	ReplicaChange(groupID string, sequence int64) (ReplicaChange, error)
	ReplicaChanges(groupID string, after int64, limit int) ([]ReplicaChange, error)
	// ReplicaVersion returns zero when no conflict marker is retained.
	ReplicaVersion(physicalName, keyID string) (int64, error)
}

type ReplicaWriter interface {
	PutReplicaBootstrap(ReplicaBootstrap) error
	// DeleteReplicaBootstrap also removes its pinned item versions.
	DeleteReplicaBootstrap(TableKey) error
	// SnapshotReplicaVersions runs under the source database gate, alongside
	// marking its immutable native snapshot Ready and retaining its Cursor.
	SnapshotReplicaVersions(target TableKey, sourcePhysicalName string) error
	// InstallReplicaVersions replaces only the new target's conflict markers,
	// in the transaction that marks the native baseline copy complete.
	InstallReplicaVersions(target TableKey, targetPhysicalName string) error
	PutReplicaVersion(physicalName, keyID string, version int64) error
	DeleteReplicaVersions(physicalName string) error
	// AppendReplicaChanges assigns positive increasing publication sequences
	// in input order; caller-supplied Sequence fields are ignored.
	AppendReplicaChanges([]ReplicaChange) error
	// TrimReplicaChanges removes acknowledged changes, then conflict markers
	// older than every remaining group change and unresolved native capture.
	// With neither remaining, all member conflict markers may be discarded.
	TrimReplicaChanges(groupID string, throughSequence int64) error
}
