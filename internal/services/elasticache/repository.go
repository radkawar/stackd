// Package elasticache owns scoped cache intent and native Valkey lifecycle work.
package elasticache

import (
	"context"
	"errors"
	engine "stackd/engine/valkey"
	"time"
)

var ErrNotFound = errors.New("elasticache resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Kind, Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":elasticache:" + k.Region + ":" + k.AccountID + ":" + k.Kind + ":" + k.Name
}

type Cluster struct {
	Key                                                                     Key
	Engine, EngineVersion, NodeType, Description, ParameterGroup, UserGroup string
	RuntimeID, Status, Operation, RestoreSnapshot                           string
	Shards, Replicas                                                        int32
	ClusterMode, TLSEnabled                                                 bool
	MemoryBytes, Version                                                    int64
	Created, Due                                                            time.Time
	Nodes                                                                   []engine.Node
	AuthHashes                                                              []string
	Parameters, Tags                                                        map[string]string
	// CloudFormationOwner is the private incarnation claim, never a public tag.
	CloudFormationOwner string
}
type Snapshot struct {
	Key                                                        Key
	SourceKind, Source, SourceRuntimeID, RuntimeID, CopySource string
	Engine, EngineVersion, NodeType, Status, Operation         string
	Shards, Replicas                                           int32
	ClusterMode, TLSEnabled                                    bool
	MemoryBytes, Version                                       int64
	Created, Due                                               time.Time
	Parameters, Tags                                           map[string]string
}
type User struct {
	Key                                Key
	Name, Engine, AccessString, Status string
	PasswordHashes                     []string
	NoPassword                         bool
	Tags                               map[string]string
	CloudFormationOwner                string
}
type UserGroup struct {
	Key                 Key
	Engine, Status      string
	UserIDs             []string
	Tags                map[string]string
	CloudFormationOwner string
}
type ParameterGroup struct {
	Key                 Key
	Family, Description string
	Parameters, Tags    map[string]string
	CloudFormationOwner string
}
type Subnet struct{ ID, VPCID, AvailabilityZone string }
type SubnetGroup struct {
	Key                 Key
	Description, VPCID  string
	Subnets             []Subnet
	Tags                map[string]string
	CloudFormationOwner string
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Cluster(Key) (Cluster, error)
	Clusters(Scope) ([]Cluster, error)
	AllClusters() ([]Cluster, error)
	Snapshot(Key) (Snapshot, error)
	Snapshots(Scope) ([]Snapshot, error)
	AllSnapshots() ([]Snapshot, error)
	User(Key) (User, error)
	Users(Scope) ([]User, error)
	UserGroup(Key) (UserGroup, error)
	UserGroups(Scope) ([]UserGroup, error)
	ParameterGroup(Key) (ParameterGroup, error)
	ParameterGroups(Scope) ([]ParameterGroup, error)
	SubnetGroup(Key) (SubnetGroup, error)
	SubnetGroups(Scope) ([]SubnetGroup, error)
}
type Transaction interface {
	Reader
	PutCluster(Cluster) error
	DeleteCluster(Key) error
	PutSnapshot(Snapshot) error
	DeleteSnapshot(Key) error
	PutUser(User) error
	DeleteUser(Key) error
	PutUserGroup(UserGroup) error
	DeleteUserGroup(Key) error
	PutParameterGroup(ParameterGroup) error
	DeleteParameterGroup(Key) error
	PutSubnetGroup(SubnetGroup) error
	DeleteSubnetGroup(Key) error
}

// Runtime is the consumer-owned native boundary. Every method receiving a
// context runs outside resource transactions; IDs are retained incarnations.
type Runtime interface {
	Ensure(context.Context, engine.Specification) (engine.Deployment, error)
	Restart(context.Context, engine.Specification) (engine.Deployment, error)
	Delete(context.Context, string) error
	Snapshot(context.Context, engine.Specification, string) error
	Restore(context.Context, engine.Specification, string) (engine.Deployment, error)
	CopySnapshot(context.Context, string, string) error
	DeleteSnapshot(context.Context, string) error
	Statistics(context.Context, engine.Specification) (engine.Statistics, error)
}
type NetworkControl interface {
	ResolveSubnets(context.Context, string, []string) ([]Subnet, error)
}
type Event struct {
	ARN, Identifier, Kind, Status, Operation string
	At                                       time.Time
}
type EventPublisher interface {
	PublishElastiCacheEvent(context.Context, Event) error
}
type Metric struct {
	ARN, Identifier, Name string
	Value                 float64
	At                    time.Time
}
type MetricPublisher interface {
	PublishElastiCacheMetric(context.Context, Metric) error
}
