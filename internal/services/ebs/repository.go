// Package ebs owns EBS snapshot metadata, sparse block contents and lifecycle.
// The EBS direct APIs and EC2 snapshot controls share this repository.
package ebs

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/ebs"
	ec2api "stackd/internal/awsapi/ec2"
)

var ErrNotFound = errors.New("ebs: snapshot resource not found")

type Scope struct{ Partition, AccountID, Region string }

type SnapshotKey struct {
	Scope
	ID string
}

// SnapshotRecord retains a parent layer while descendants still reference its
// data. Deleted snapshots disappear immediately from EC2; DeleteAt ends their
// bounded EBS direct-plane visibility without discarding referenced layers.
// InitialInput preserves StartSnapshot's native idempotent response and comparison.
// Completed and readable are separate transitions: EC2 completion does not imply
// that the EBS direct APIs can already use the snapshot.
type SnapshotRecord struct {
	Key                                         SnapshotKey
	ParentID, LineageID                         string
	VolumeSize                                  int64
	Description                                 string
	Copy                                        *SnapshotCopy
	Volume                                      *SnapshotVolume
	InitialInput                                api.StartSnapshotRequest
	Created                                     time.Time
	Status                                      api.Status
	Sealed, Readable, Deleted                   bool
	CompleteAt, ReadableAt, TimeoutAt, DeleteAt time.Time
	StateMessage                                string
	Tags                                        map[string]string
	Public                                      bool
	Shares                                      []SnapshotShare
	SharingAt                                   time.Time
	KMSKeyARN                                   string
	WrappedKey                                  []byte
	// TokenKey authenticates the public API's expiring block/page tokens.
	TokenKey []byte
}

// SnapshotCopy retains admitted source and key authority until payload work
// completes. Source identity remains after WorkAt clears.
type SnapshotCopy struct {
	Source                                                                SnapshotKey
	Incremental                                                           bool
	CompletionDurationMinutes                                             int32
	RequestID, ParentEventID                                              string
	WorkAt                                                                time.Time
	KeySource                                                             SnapshotKey
	SourceGrantToken, DestinationGrantToken, DestinationEncryptGrantToken string
}

// SnapshotShare separates current EC2 permissions from their delayed direct-API
// visibility. SharingAt publishes the current grants through the shared clock.
type SnapshotShare struct {
	AccountID         string
	Granted, Readable bool
}

type BlockKey struct {
	Snapshot SnapshotKey
	Index    int32
}

// BlockInfo permits listing and completion without reading or copying payloads.
// Checksum is SHA256 of the plaintext 512-KiB block.
type BlockInfo struct {
	Key      BlockKey
	Checksum [32]byte
	// WrittenSnapshotID identifies the logical write within the lineage.
	// A copy changes physical Key without creating a new write.
	WrittenSnapshotID string
	EncryptionOrigin  BlockEncryptionOrigin
}

type BlockRecord struct {
	BlockInfo
	Data []byte
}

type EncryptionDefault struct {
	Scope    Scope
	Enabled  bool
	KMSKeyID string
}

// SnapshotPublicAccess is the account's regional setting. Organization policy
// overrides are read from their owner rather than copied into this record.
type SnapshotPublicAccess struct {
	Scope Scope
	State ec2api.SnapshotBlockPublicAccessState
}

// SharedTagsKey addresses the recipient's private tags, not the owner's tags.
type SharedTagsKey struct {
	Snapshot  SnapshotKey
	AccountID string
}

type SnapshotTag struct {
	Snapshot   SnapshotKey
	Key, Value string
}

// SnapshotCounts admits new snapshots without materializing the regional catalog.
// Deleted snapshots do not contribute; Copying counts pending copy snapshots.
type SnapshotCounts struct{ Total, Pending, Copying int64 }

// Reader returns detached records and borrows the shared transaction through
// Context. Block methods address one layer; the service resolves parent lineage.
type Reader interface {
	Context() context.Context
	Snapshot(SnapshotKey) (SnapshotRecord, error)
	Snapshots(Scope) ([]SnapshotRecord, error)
	// RegionalSnapshot resolves an owner; it does not grant access. The service
	// applies the operation's ownership, sharing and public-access rules.
	RegionalSnapshot(partition, region, id string) (SnapshotRecord, error)
	// AvailableSnapshots includes owned, explicitly shared and public candidates.
	// The service applies the owner's effective public-access setting.
	AvailableSnapshots(Scope) ([]SnapshotRecord, error)
	SnapshotCounts(Scope) (SnapshotCounts, error)
	SnapshotByToken(Scope, string) (SnapshotRecord, error)
	Block(BlockKey) (BlockRecord, error)
	Blocks(SnapshotKey) ([]BlockInfo, error)
	EncryptionDefault(Scope) (EncryptionDefault, error)
	SnapshotPublicAccess(Scope) (SnapshotPublicAccess, error)
	SharedTags(SharedTagsKey) (map[string]string, error)
	TagsForAccount(Scope) ([]SnapshotTag, error)
	NextWork() (SnapshotRecord, error)
	// PendingSnapshotSources returns source-layer roots in this scope referenced
	// by pending copies or volume creations in any destination account or region.
	PendingSnapshotSources(Scope) ([]SnapshotKey, error)
	Volume(VolumeKey) (VolumeRecord, error)
	Volumes(Scope) ([]VolumeRecord, error)
	VolumeByToken(Scope, string) (VolumeRecord, error)
	VolumeBlock(VolumeBlockKey) (VolumeBlockRecord, error)
	VolumeBlocks(VolumeKey) ([]VolumeBlockInfo, error)
	// VolumeSnapshotBlocksPending retains the admitted SQL block set while any
	// snapshot still needs it, including a deleted snapshot awaiting cleanup.
	VolumeSnapshotBlocksPending(VolumeKey) (bool, error)
	NextVolumeWork() (VolumeRecord, error)
}

type Transaction interface {
	Reader
	NextID(Scope) (string, error)
	PutSnapshot(SnapshotRecord) error
	DeleteSnapshot(SnapshotKey) error
	PutBlock(BlockRecord) error
	DeleteBlocks(SnapshotKey) error
	PutEncryptionDefault(EncryptionDefault) error
	PutSnapshotPublicAccess(SnapshotPublicAccess) error
	PutSharedTags(SharedTagsKey, map[string]string) error
	NextVolumeID(Scope) (string, error)
	PutVolume(VolumeRecord) error
	PutVolumeBlock(VolumeBlockRecord) error
	DeleteVolumeBlocks(VolumeKey) error
}

// Repository joins state transitions, authorization and API events in one shared
// transaction. External effects must remain outside repository callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
