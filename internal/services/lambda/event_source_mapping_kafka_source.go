package lambda

import (
	"context"
	"time"
)

// KafkaSource uses current function execution-role authority for Kafka and secrets.
// Open must fence every operation to the retained native cluster/topic identity.
type KafkaSource interface {
	Open(context.Context, FunctionKey, string, EventSourceMappingRecord) (KafkaConsumer, error)
}

// KafkaConsumer owns native coordinator membership, never a Lambda offset ledger.
// Offsets are next offsets. Lease cancellation revokes delivery and commit rights.
type KafkaConsumer interface {
	// Check validates current control-plane access without contacting the broker.
	Check(context.Context) error
	Identity(context.Context) (KafkaIdentity, error)
	BootstrapServers(context.Context) (string, error)
	Assignments(context.Context) ([]KafkaPartition, error)
	Fetch(context.Context, int, int64, int) (KafkaPage, error)
	Commit(context.Context, map[int]int64) error
	Lease(context.Context, int) (context.Context, context.CancelFunc, error)
	Close() error
}
type KafkaIdentity struct{ ClusterID, TopicID string }

// FirstOffset is the broker's current log start, not a Lambda retention estimate.
type KafkaPartition struct {
	ID                  int
	Offset, FirstOffset int64
	Committed           bool
}
type KafkaPage struct {
	Records    []KafkaRecord
	NextOffset int64
}
type KafkaRecord struct {
	Partition     int
	Offset        int64
	Timestamp     time.Time
	TimestampType string
	Key, Value    []byte
	Headers       []KafkaHeader
}
type KafkaHeader struct {
	Key   string
	Value []byte
}

// KafkaMappingSettings retains immutable source identity, not message receipts.
type KafkaMappingSettings struct {
	Topic, ConsumerGroupID, StartingPosition string
	StartingPositionTimestamp                time.Time
	SecretARN, Authentication                string
	BootstrapServers                         []string
	RootCASecretARN                          string
	Network                                  SourceNetworkConfiguration
	NetworkRoleARN                           string
	Identity                                 KafkaIdentity
}
