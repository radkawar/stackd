// Package docdb provides an explicit local MongoDB compatibility backend for
// DocumentDB. MongoDB is not AWS DocumentDB: this backend does not implement
// AWS storage, failover, capacity, VPC networking or complete query semantics.
// Documents and change streams come only from the native MongoDB engine.
//
// The installed MongoDB 7.0.43 backend requires verified TLS and SCRAM passwords
// accepted by the official driver's SASLprep profile. Consumers explicitly trust
// Endpoint.CA; no system trust installation or insecure TLS fallback occurs.
// Normal replica discovery and resumable native change streams work through the
// returned host-loopback endpoint. Cold snapshots retain native documents, users
// and oplog, while a restored incarnation receives its own endpoint and TLS key.
// They are not point-in-time, continuously replicated or online AWS backups.
package docdb

import "context"

// Specification identifies an immutable, globally unique database incarnation.
// Password is supplied at the native boundary; callers must encrypt credentials
// in control-plane storage. Native bootstrap secrets stay in private files.
// Port is a host loopback port; zero selects one at initial creation. A retained
// incarnation keeps its port, including across controller/container replacement.
type Specification struct {
	ID, Username, Password string
	Port                   int32
}

// Endpoint is the authoritative native connection, including explicitly trusted
// PEM CA certificates. TLS and admin-database SCRAM authentication are required.
// The single replica member advertises localhost:Port, reachable from the Docker
// host without directConnection. Remote Docker requires an explicit localhost
// tunnel preserving that port; container-network clients need a host-side route.
type Endpoint struct {
	Address    string
	Port       int32
	ReplicaSet string
	CA         []byte
}

// Runtime owns exact namespace/incarnation resources, not control-plane names.
// Close detaches without deleting or stopping databases. Snapshot is a cold
// physical copy, briefly stopping the source; restore requires a new incarnation
// and the credentials captured by the snapshot. Tokens from native change streams
// must be scoped to their control-plane incarnation by consumers.
type Runtime interface {
	Ensure(context.Context, Specification) (Endpoint, error)
	Stop(context.Context, string) error
	Delete(context.Context, string) error
	Snapshot(context.Context, Specification, string) error
	Restore(context.Context, Specification, string) (Endpoint, error)
	DeleteSnapshot(context.Context, string) error
	SetPassword(context.Context, Specification, string) error
	Close() error
}
