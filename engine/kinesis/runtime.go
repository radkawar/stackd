// Package kinesis defines the imported record-engine boundary. The Go service
// owns AWS identity, shard routing, consumers, authorization and retention time.
package kinesis

import (
	"context"
	"time"
)

// Runtime prepares or reopens one stream's owned record log. Open succeeds only
// after the native engine answers requests. Remove also cleans up a partially
// prepared stream. Neither operation runs inside a repository transaction.
type Runtime interface {
	Open(context.Context, Specification) (Log, error)
	Remove(context.Context, Specification) error
}

// Specification identifies one retained stream incarnation independently of its
// AWS name. Recreating a deleted stream must allocate a new ID.
type Specification struct {
	ID                           string
	Partition, AccountID, Region string
}

// Log stores records in native partitions. Partition numbers never change or
// disappear during a stream incarnation: closed AWS shards retain their logs.
// Automatic engine retention is disabled; the service chooses trim offsets
// using its own clock. Close detaches this process; Runtime.Remove destroys data.
type Log interface {
	// EnsurePartitions grows the native partition count to at least count. It
	// is idempotent so an interrupted shard transition can resume on reopen.
	EnsurePartitions(context.Context, int32) error
	// Append writes one partition atomically and returns the first native
	// offset. The supplied timestamps are retained; input offsets are ignored.
	Append(context.Context, int32, []Record) (int64, error)
	// Read returns up to limit records, bounded by maxBytes except that the
	// first record is always returned so a large record can make progress.
	Read(context.Context, int32, int64, int, int) (ReadResult, error)
	Bounds(context.Context, int32) (Bounds, error)
	// OffsetAt finds the first record at or after at, or the exclusive end
	// offset if no such retained record exists.
	OffsetAt(context.Context, int32, time.Time) (int64, error)
	// Trim discards the native prefix strictly before before.
	Trim(context.Context, int32, int64) error
	Close() error
}

// Record uses a native offset, producer-supplied arrival time, partition key and
// exact bytes. AWS sequence numbers are derived by the service, not the engine.
type Record struct {
	Offset       int64
	Timestamp    time.Time
	PartitionKey string
	Data         []byte
	// Metadata is opaque service-owned information, such as the wrapped data
	// key for an encrypted record, retained in a native record header.
	Metadata []byte
}

// Bounds describes the retained native interval [Start, End). End is the next
// append offset and remains meaningful when the retained interval is empty.
type Bounds struct {
	Start int64
	End   int64
}

type ReadResult struct {
	Records []Record
	Bounds  Bounds
}
