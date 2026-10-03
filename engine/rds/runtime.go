// Package rds runs native PostgreSQL and MySQL databases. Aurora engine names
// select the corresponding SQL engine, not Aurora storage or failover semantics.
package rds

import "context"

// Specification identifies one immutable database incarnation. Password is only
// used at the native boundary and must not be persisted in control-plane state.
// Port is the host-side port; zero asks Docker to allocate one. Parameters are
// native server settings, validated against the supported engine settings.
type Specification struct {
	ID, Engine, Database, Username, Password string
	Port                                     int32
	Parameters                               map[string]string
}

type Endpoint struct {
	Address string
	Port    int32
}

// Statistics contains measured native counters, not provisioned capacity.
type Statistics struct{ Connections int64 }

// Runtime owns durable native processes and backups. Close detaches without
// stopping or deleting anything. Delete and DeleteSnapshot retire exact-owned
// resources. Snapshot identifiers, like database IDs, must be globally unique.
// Ensure persists and applies supported dynamic parameter changes without
// restarting a running engine. Static parameters and port changes require a
// process replacement; callers must admit those only at a restart boundary.
type Runtime interface {
	Ensure(context.Context, Specification) (Endpoint, error)
	Stop(context.Context, string) error
	Delete(context.Context, string) error
	Snapshot(context.Context, Specification, string) error
	Restore(context.Context, Specification, string) (Endpoint, error)
	DeleteSnapshot(context.Context, string) error
	SetPassword(context.Context, Specification, string) error
	Statistics(context.Context, Specification) (Statistics, error)
	Close() error
}
