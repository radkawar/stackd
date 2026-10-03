package kms

import (
	"context"
	"errors"
	"time"
)

// StorageScope identifies one independent KMS key namespace.
type StorageScope struct{ Partition, AccountID, Region string }

// KeyOwner scopes shared key properties across Regions in one AWS partition.
type KeyOwner struct{ Partition, AccountID string }

var ErrKeySetNotFound = errors.New("KMS key material set does not exist")

// KeyRecord stores a regional KMS key and references its key set by ID.
// Records returned by a transaction belong to the caller and may be modified.
type KeyRecord struct {
	ID, ARN, Description, Manager, State string
	Created                              time.Time
	Deletion                             *time.Time
	AvailableAt                          time.Time
	PendingDeletionWindowInDays          int32
	Policy                               string
	Principals                           []PrincipalBinding
	Tags                                 []TagRecord
	Grants                               []GrantRecord
	Imports                              []ImportedMaterialRecord
	ImportParameters                     []ImportParametersRecord
}

// KeySetRecord owns material and rotation once for a key ID. A single-Region
// key has only PrimaryRegion; related multi-Region keys reference the same
// record. Material must be protected by storage and never exposed by AWS APIs.
// Regional records retain independent policies, aliases, tags and enabled state.
type KeySetRecord struct {
	ID, Spec, Usage, Origin string
	CurrentMaterialID       string
	PendingMaterialID       string
	Materials               []KeyMaterialRecord
	Rotation                RotationState
	MultiRegion             bool
	PrimaryRegion           string
	ReplicaRegions          []string
}

// KeyMaterialRecord retains one cryptographic version. Materials are stored in
// creation order; KeySetRecord identifies the current and pending versions.
// Imported IDs bind material to a key even after its bytes are deleted.
type KeyMaterialRecord struct {
	ID           string
	Material     []byte
	RotationDate time.Time
	RotationType string
	Description  string
}

// RotationState retains automatic scheduling and an accepted on-demand request.
// Enabled records configurable rotation; AWS-managed keys have a fixed schedule.
// Zero timestamps mean no scheduled rotation or no pending request.
type RotationState struct {
	Enabled         bool
	PeriodInDays    int32
	Next            time.Time
	OnDemandStarted time.Time
}

type PrincipalBinding struct{ Reference, ID string }
type TagRecord struct{ Key, Value string }

// GrantRecord retains immutable principals and all interchangeable grant tokens.
// Regional EC2 service names remain in Grantee/Retiring with empty principal IDs.
type GrantRecord struct {
	ID, Name, Grantee, GranteeID, Retiring, RetiringID, Issuer string
	Created                                                    time.Time
	Operations, Tokens                                         []string
	EncryptionContextEquals, EncryptionContextSubset           []TagRecord
}

// AliasOwner identifies a trusted service's alias independently of its name.
// The zero value denotes an unowned legacy or natively created alias.
type AliasOwner struct{ StackID, LogicalID, Token string }

// AliasRecord refers to a key in the same StorageScope.
type AliasRecord struct {
	Name, KeyID      string
	Created, Updated time.Time
	Owner            AliasOwner
}

// Storage supplies serializable, atomic transactions across KMS namespaces.
// If fn returns an error, none of its writes may become visible. Implementations
// must propagate context cancellation and return independent record copies.
// The callback must not be retried: it can generate fresh cryptographic material.
type Storage interface {
	// View observes one consistent snapshot without permitting writes.
	View(context.Context, func(Reader) error) error
	Transact(context.Context, func(Transaction) error) error
	// Attempt isolates a rejected command from an enclosing service transaction.
	Attempt(context.Context, func(Transaction) error) error
}

// Reader exposes service-owned resources without leaking storage maps,
// locks, SQL handles, or backend-specific serialization into service logic.
type Reader interface {
	// Context joins related repositories to this transaction. Do not retain it
	// after the callback or use it concurrently.
	Context() context.Context
	// Scopes lists namespaces containing regional keys, in lexical scope order.
	Scopes() ([]StorageScope, error)
	KeySet(KeyOwner, string) (KeySetRecord, error)
	MultiRegionPrimaryRegions(KeyOwner) ([]string, error)
	Keys(StorageScope) ([]KeyRecord, error)
	Aliases(StorageScope) ([]AliasRecord, error)
}

// Transaction adds mutations to the callback-scoped Reader.
type Transaction interface {
	Reader
	PutKeySet(KeyOwner, KeySetRecord) error
	DeleteKeySet(KeyOwner, string) error
	PutKey(StorageScope, KeyRecord) error
	DeleteKey(StorageScope, string) error
	PutAlias(StorageScope, AliasRecord) error
	DeleteAlias(StorageScope, string) error
}

func storageScope(sc scope) StorageScope {
	return StorageScope{Partition: sc.partition, AccountID: sc.account, Region: sc.region}
}
