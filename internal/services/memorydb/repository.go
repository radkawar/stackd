// Package memorydb owns scoped MemoryDB controls and retained native Valkey intent.
package memorydb

import (
	"context"
	"errors"
	engine "stackd/engine/valkey"
	"time"
)

var ErrNotFound = errors.New("memorydb resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Kind, Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":memorydb:" + k.Region + ":" + k.AccountID + ":" + k.Kind + "/" + k.Name
}

type Cluster struct {
	Key                                                                                                                  Key
	RuntimeID, Status, Operation, Description, NodeType, Engine, EngineVersion, ACLName, ParameterGroup, RestoreSnapshot string
	Shards, Replicas                                                                                                     int32
	TLSEnabled                                                                                                           bool
	Version                                                                                                              int64
	Created, Due                                                                                                         time.Time
	Deployment                                                                                                           engine.Deployment
	Tags                                                                                                                 map[string]string
}
type User struct {
	Key                                  Key
	AccessString, Authentication, Status string
	PasswordHashes                       []string
	Tags                                 map[string]string
}
type ACL struct {
	Key    Key
	Status string
	Users  []string
	Tags   map[string]string
}
type ParameterGroup struct {
	Key                 Key
	Family, Description string
	Parameters, Tags    map[string]string
}
type Subnet struct{ ID, VPCID, AvailabilityZone string }
type SubnetGroup struct {
	Key                Key
	Description, VPCID string
	Subnets            []Subnet
	Tags               map[string]string
}
type Snapshot struct {
	Key                                                                                                                         Key
	RuntimeID, SourceRuntimeID, Source, CopySource, Status, Operation, Engine, EngineVersion, NodeType, ParameterGroup, ACLName string
	Shards, Replicas                                                                                                            int32
	TLSEnabled                                                                                                                  bool
	Version                                                                                                                     int64
	Created, Due                                                                                                                time.Time
	Tags                                                                                                                        map[string]string
}

// Transactions join the resource/journal domain. Native effects run outside them.
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
	User(Key) (User, error)
	Users(Scope) ([]User, error)
	ACL(Key) (ACL, error)
	ACLs(Scope) ([]ACL, error)
	ParameterGroup(Key) (ParameterGroup, error)
	ParameterGroups(Scope) ([]ParameterGroup, error)
	SubnetGroup(Key) (SubnetGroup, error)
	SubnetGroups(Scope) ([]SubnetGroup, error)
	Snapshot(Key) (Snapshot, error)
	Snapshots(Scope) ([]Snapshot, error)
	AllSnapshots() ([]Snapshot, error)
}
type Transaction interface {
	Reader
	PutCluster(Cluster) error
	DeleteCluster(Key) error
	PutUser(User) error
	DeleteUser(Key) error
	PutACL(ACL) error
	DeleteACL(Key) error
	PutParameterGroup(ParameterGroup) error
	DeleteParameterGroup(Key) error
	PutSubnetGroup(SubnetGroup) error
	DeleteSubnetGroup(Key) error
	PutSnapshot(Snapshot) error
	DeleteSnapshot(Key) error
}

// Runtime is the consumer-owned native boundary; it never owns control-plane state.
type Runtime interface {
	Ensure(context.Context, engine.Specification) (engine.Deployment, error)
	Delete(context.Context, string) error
	Snapshot(context.Context, engine.Specification, string) error
	Restore(context.Context, engine.Specification, string) (engine.Deployment, error)
	DeleteSnapshot(context.Context, string) error
	CopySnapshot(context.Context, string, string) error
	Statistics(context.Context, engine.Specification) (engine.Statistics, error)
}
type NetworkControl interface {
	ResolveSubnets(context.Context, string, []string) ([]Subnet, error)
}
type Event struct {
	ARN, Name, Kind, Status, Operation, Message string
	At                                          time.Time
}
type EventPublisher interface {
	PublishMemoryDBEvent(context.Context, Event) error
}
type Metric struct {
	ARN, ClusterName, Name string
	Value                  float64
	At                     time.Time
}
type MetricPublisher interface {
	PublishMemoryDBMetric(context.Context, Metric) error
}
