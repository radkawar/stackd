// Package valkey owns the native Valkey mechanics shared by ElastiCache and
// MemoryDB. It is not an AWS control plane or a general engine manager.
package valkey

import "context"

const Version = "8.1.6"
const RedisCompatibility = "7.2"

// User contains one effective native ACL. PasswordHashes are SHA256 hex digests,
// not recoverable credentials. The service owns authentication admission.
type User struct {
	Name, AccessString string
	PasswordHashes     []string
	NoPassword         bool
}

// Specification identifies immutable topology and current effective settings.
// ID must be a persisted globally unique incarnation, not a resource name.
type Specification struct {
	MemoryBytes             int64
	ID                      string
	Shards, Replicas        int32
	ClusterMode, TLSEnabled bool
	Users                   []User
	Parameters              map[string]string
}
type Endpoint struct {
	Address string
	Port    int32
}
type Node struct {
	ID             string
	Shard, Replica int32
	Endpoint       Endpoint
}
type Deployment struct {
	Nodes    []Node
	Endpoint Endpoint
}
type Statistics struct{ Connections, UsedMemory, KeyspaceHits, KeyspaceMisses, Commands int64 }

// Runtime is the public embedding contract; services define their own narrower
// consumer interfaces. Close detaches. Only Delete retires native resources.
type Runtime interface {
	Ensure(context.Context, Specification) (Deployment, error)
	Restart(context.Context, Specification) (Deployment, error)
	Delete(context.Context, string) error
	Snapshot(context.Context, Specification, string) error
	Restore(context.Context, Specification, string) (Deployment, error)
	CopySnapshot(context.Context, string, string) error
	DeleteSnapshot(context.Context, string) error
	Statistics(context.Context, Specification) (Statistics, error)
	Close() error
}
