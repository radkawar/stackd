// Package secretsmanager owns secret values, immutable versions, staging labels,
// policies and lifecycle transitions behind the generated AWS frontend.
package secretsmanager

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/secretsmanager"
)

var ErrNotFound = errors.New("secret resource not found")

type Scope struct{ Partition, AccountID, Region string }

type SecretKey struct {
	Scope
	Name string
}

type VersionKey struct {
	Secret SecretKey
	ID     string
}

// SecretRecord owns metadata and incarnation identity. Values live in immutable
// versions; staging labels select those versions without copying their values.
type SecretRecord struct {
	Key                                                                SecretKey
	ARN                                                                string
	Type                                                               string
	Description                                                        *string
	KMSKeyID, OwningService                                            string
	Created, Changed                                                   time.Time
	LastAccessed                                                       *time.Time
	Deleted, DeleteAfter                                               *time.Time
	Tags                                                               map[string]string
	Policy                                                             authorization.BoundPolicy
	RotationEnabled                                                    *bool
	RotationLambdaARN                                                  string
	RotationRules                                                      *api.RotationRulesType
	LastRotated, NextRotation                                          *time.Time
	RotationDue                                                        *time.Time
	PrimaryRegion                                                      string
	Ownership, PolicyOwnership, RotationOwnership, AttachmentOwnership CloudFormationOwnership
	AttachmentMetadata                                                 SecretTargetMetadata
}

// SealedValue is one KMS-backed encryption of an immutable version. Changing a
// secret's configured KMS key can retain more than one encryption of that value.
// KeyID is the public KMS identity, including native DefaultEncryptionKey.
type SealedValue struct {
	KeyID               string
	WrappedKey, Payload []byte
}

type VersionRecord struct {
	Key          VersionKey
	Binary       bool
	Stages       []string
	Created      time.Time
	LastAccessed *time.Time
}

type ReplicaKey struct {
	Primary SecretKey
	Region  string
}

type ReplicaRecord struct {
	Key                   ReplicaKey
	PrimaryARN, KMSKeyID  string
	Status, StatusMessage string
	Due                   *time.Time
}

// RotationRecord retains the current Lambda step; the callback itself executes
// outside the transaction and must be idempotent for its version token.
type RotationRecord struct {
	Secret          SecretKey
	ARN, Token      string
	InvocationToken string
	Step, Attempt   int
	TestOnly        bool
	Due, Deadline   time.Time
	LastError       string
}

// Reader returns detached records scoped to the repository callback. Context
// borrows the shared transaction for related IAM and API-event operations.
type Reader interface {
	Context() context.Context
	Secret(SecretKey) (SecretRecord, error)
	Secrets(Scope) ([]SecretRecord, error)
	Version(VersionKey) (VersionRecord, error)
	Versions(SecretKey) ([]VersionRecord, error)
	// Payloads are separate so metadata and label operations never copy secret bytes.
	EncryptedVersion(VersionKey) ([]SealedValue, error)
	VersionKeyIDs(VersionKey) ([]string, error)
	NextDeletion() (SecretRecord, error)
	Replica(ReplicaKey) (ReplicaRecord, error)
	Replicas(SecretKey) ([]ReplicaRecord, error)
	NextReplica() (ReplicaRecord, error)
	Rotation(SecretKey) (RotationRecord, error)
	NextRotationWork() (RotationRecord, error)
	NextScheduledRotation() (SecretRecord, error)
}

type Transaction interface {
	Reader
	PutSecret(SecretRecord) error
	DeleteSecret(SecretKey) error
	PutVersion(VersionRecord) error
	PutEncryptedVersion(VersionKey, []SealedValue) error
	DeleteVersion(VersionKey) error
	PutReplica(ReplicaRecord) error
	DeleteReplica(ReplicaKey) error
	PutRotation(RotationRecord) error
	DeleteRotation(SecretKey) error
}

// Repository joins resource mutations and API events in the shared transaction
// domain. Network and compute effects must execute outside its callbacks.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
