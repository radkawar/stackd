package ebs

import (
	"time"

	ec2api "stackd/internal/awsapi/ec2"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/services/ec2"
)

// VolumeKey identifies an account-owned regional disk; its zone is retained in
// the record rather than creating another resource namespace.
type VolumeKey struct {
	Scope
	ID string
}

// VolumeConfiguration is the disk configuration changed by Elastic Volumes.
// Zero Iops/Throughput means the field does not apply to the selected type.
type VolumeConfiguration struct {
	Size        int32
	Type        ec2api.VolumeType
	Iops        int32
	Throughput  int32
	MultiAttach bool
}

// VolumeRecord owns independent disk contents. SnapshotID is provenance, not a
// dependency on the source snapshot's continued existence or sharing policy.
// CreationInput retains admitted request identity for native client-token replay.
type VolumeRecord struct {
	Key                   VolumeKey
	CloudFormationOwner   ec2.CloudFormationOwner
	Configuration         VolumeConfiguration
	ZoneName, ZoneID      string
	SnapshotID, LineageID string
	Created, TransitionAt time.Time
	SnapshotAt            time.Time
	Status                ec2api.VolumeState
	StateMessage          string
	AutoEnableIO          bool
	InitializationRate    int32
	Tags                  map[string]string
	Encrypted             bool
	KMSKeyARN             string
	WrappedKey            []byte
	// Creation pins an admitted immutable source until all independent volume
	// blocks have committed. Public source visibility is no longer consulted.
	Creation *VolumeCreation
	// NativePath is set only after complete hydration. Its bytes then own
	// current contents; admitted snapshots can still pin the old SQL blocks.
	NativePath               string
	ServiceGrantID           kmsapi.GrantIdType
	InfrastructureGrantID    kmsapi.GrantIdType
	CreationInput            ec2api.CreateVolumeRequest
	RequestID, ParentEventID string
	Modification             *VolumeModification
	ModificationStarts       []time.Time
}

// VolumeCreation retains only the authority needed to resume hydration. The
// source data key is wrapped into the destination CMK and volume context.
type VolumeCreation struct {
	Source                SnapshotKey
	SourceWrappedKey      []byte
	ReuseSourceCiphertext bool
	RetireGrant           bool
}

// VolumeModification retains original and target settings until the shared
// scheduler completes the accepted transition, independently of client polling.
type VolumeModification struct {
	Original, Target                   VolumeConfiguration
	Started, OptimizingAt, CompletedAt time.Time
	State                              ec2api.VolumeModificationState
	RequestID, ParentEventID           string
	StatusMessage                      string
}

// BlockEncryptionOrigin is the immutable resource identity authenticated by the
// local block cipher. Moving encrypted bytes between a snapshot and volume does
// not change that identity or require an unobserved KMS decrypt operation.
type BlockEncryptionOrigin struct {
	Scope
	ID string
}

type VolumeBlockKey struct {
	Volume VolumeKey
	Index  int32
}

// VolumeBlockInfo retains the logical write identity when snapshot bytes are
// hydrated into a volume and snapshotted again without a guest write.
type VolumeBlockInfo struct {
	Key               VolumeBlockKey
	Checksum          [32]byte
	WrittenSnapshotID string
	EncryptionOrigin  BlockEncryptionOrigin
}

type VolumeBlockRecord struct {
	VolumeBlockInfo
	Data []byte
}

// SnapshotVolume identifies the volume consumed by EC2 CreateSnapshot and the
// originating request for its asynchronous completion event.
type SnapshotVolume struct {
	Source                   VolumeKey
	RequestID, ParentEventID string
	// BlocksWorkAt pins the immutable standalone VolumeBlocks chosen at
	// admission, even after deletion or a handoff to native byte authority.
	BlocksWorkAt time.Time
	// NativeBackupPath is a temporary independent qcow2 capture, never a
	// published snapshot format. Ready is set only after actual backup completion.
	// Until it is removed, the source service grant must remain usable.
	NativeBackupPath  string
	NativeBackupReady bool
	NativeWorkAt      time.Time
}
