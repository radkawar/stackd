// Package docdb owns DocumentDB controls over an explicit native compatibility backend.
package docdb

import (
	"context"
	"errors"
	engine "stackd/engine/docdb"
	"time"
)

var ErrNotFound = errors.New("DocumentDB resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Kind, Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":rds:" + k.Region + ":" + k.AccountID + ":" + k.Kind + ":" + k.Name
}

// Cluster holds native effect intent, never plaintext credentials or document data.
// RuntimeID and Version fence completion against deletion, replacement and mutation.
type Cluster struct {
	Key                                                                    Key
	Owner                                                                  CloudFormationOwner
	RuntimeID, Username, EngineVersion, Status, Operation, RestoreSnapshot string
	Ciphertext, PendingCiphertext                                          []byte
	Endpoint                                                               engine.Endpoint
	RequestedPort                                                          int32
	Version                                                                int64
	Created, Due                                                           time.Time
	DeletionProtection                                                     bool
	Tags                                                                   map[string]string
}
type Instance struct {
	Key                               Key
	Owner                             CloudFormationOwner
	Cluster, Class, RuntimeID, Status string
	Created                           time.Time
	Tags                              map[string]string
}
type Snapshot struct {
	Key                                                                            Key
	Owner                                                                          CloudFormationOwner
	Source, SourceRuntimeID, RuntimeID, Username, EngineVersion, Status, Operation string
	Ciphertext                                                                     []byte
	Version                                                                        int64
	Created, Due                                                                   time.Time
	Tags                                                                           map[string]string
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Cluster(Key) (Cluster, error)
	Clusters() ([]Cluster, error)
	Instance(Key) (Instance, error)
	Instances() ([]Instance, error)
	Snapshot(Key) (Snapshot, error)
	Snapshots() ([]Snapshot, error)
}
type Transaction interface {
	Reader
	PutCluster(Cluster) error
	DeleteCluster(Key) error
	PutInstance(Instance) error
	DeleteInstance(Key) error
	PutSnapshot(Snapshot) error
	DeleteSnapshot(Key) error
}
type CredentialCipher interface {
	Seal(context.Context, string, string, string) ([]byte, error)
	Open(context.Context, string, []byte) (string, string, error)
}

// SourceCluster is an authoritative connection lookup. It intentionally contains
// no database password; consumers authenticate with their own current secret.
type SourceCluster struct {
	ARN, RuntimeID, Status string
	Endpoint               engine.Endpoint
	Ready                  bool
}
