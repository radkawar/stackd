// Package rds owns relational database controls and retained native engine intent.
package rds

import (
	"context"
	"errors"
	"time"

	engine "stackd/engine/rds"
)

var ErrNotFound = errors.New("rds resource not found")

type Scope struct {
	Partition, AccountID, Region string
}
type Key struct {
	Scope
	Kind, Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":rds:" + k.Region + ":" + k.AccountID + ":" + k.Kind + ":" + k.Name
}

// Database retains controls, never a plaintext password. Cluster writer members
// reference the cluster's incarnation; they do not own another native database.
// Version fences all runtime completions, including a deleted/recreated name.
type Database struct {
	Key                                                                  Key
	Engine, EngineVersion, DatabaseName, Username, Class, ParameterGroup string
	Cluster, RuntimeID, Status, Desired, Operation, RestoreSnapshot      string
	Ciphertext, PendingCiphertext                                        []byte
	Endpoint                                                             engine.Endpoint
	RequestedPort                                                        int32
	Version                                                              int64
	Created, Due                                                         time.Time
	DeletionProtection, HTTPEnabled, CopyTags, PendingParameters         bool
	Tags                                                                 map[string]string
	Parameters                                                           map[string]string
}

type Snapshot struct {
	Key                                                                                              Key
	Source, SourceRuntimeID, RuntimeID, Engine, EngineVersion, DatabaseName, Username, Class, Status string
	Ciphertext                                                                                       []byte
	Parameters, Tags                                                                                 map[string]string
	Version                                                                                          int64
	Created, Due                                                                                     time.Time
}

type ParameterGroup struct {
	Key                            Key
	Family, Description            string
	Parameters, ApplyMethods, Tags map[string]string
}
type Subnet struct {
	ID, VPCID, AvailabilityZone string
}
type SubnetGroup struct {
	Key                Key
	Description, VPCID string
	Subnets            []Subnet
	Tags               map[string]string
}

// Native effects must run after these callbacks close. Update and Attempt join
// the shared resource/journal domain; Attempt supplies a command savepoint.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Database(Key) (Database, error)
	Databases(Scope) ([]Database, error)
	AllDatabases() ([]Database, error)
	Snapshot(Key) (Snapshot, error)
	Snapshots(Scope) ([]Snapshot, error)
	AllSnapshots() ([]Snapshot, error)
	ParameterGroup(Key) (ParameterGroup, error)
	ParameterGroups(Scope) ([]ParameterGroup, error)
	SubnetGroup(Key) (SubnetGroup, error)
	SubnetGroups(Scope) ([]SubnetGroup, error)
}
type Transaction interface {
	Reader
	PutDatabase(Database) error
	DeleteDatabase(Key) error
	PutSnapshot(Snapshot) error
	DeleteSnapshot(Key) error
	PutParameterGroup(ParameterGroup) error
	DeleteParameterGroup(Key) error
	PutSubnetGroup(SubnetGroup) error
	DeleteSubnetGroup(Key) error
}

// CredentialCipher delegates durable authenticated encryption to the KMS owner.
// ARN is authenticated associated context, so ciphertext cannot change owners.
type CredentialCipher interface {
	Seal(context.Context, string, string, string) ([]byte, error)
	Open(context.Context, string, []byte) (string, string, error)
}

// NetworkControl resolves live EC2 authority, not a duplicate VPC registry.
type NetworkControl interface {
	ResolveSubnets(context.Context, string, []string) ([]Subnet, error)
	ValidateSecurityGroups(context.Context, string, string, []string) error
}
type RDSEvent struct {
	ARN, Identifier, Kind, Status, Operation, Message string
	At                                                time.Time
}
type EventPublisher interface {
	PublishRDSEvent(context.Context, RDSEvent) error
}
type RDSMetric struct {
	ARN, Identifier, Name string
	Value                 float64
	At                    time.Time
}
type MetricPublisher interface {
	PublishRDSMetric(context.Context, RDSMetric) error
}

type DataCluster struct {
	ARN, Engine, Database, Status string
	Endpoint                      engine.Endpoint
	HTTPEnabled                   bool
	Tags                          map[string]string
}
