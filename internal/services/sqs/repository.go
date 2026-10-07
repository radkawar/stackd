package sqs

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
)

var ErrNotFound = errors.New("SQS record not found")

// QueueKey is the complete AWS resource scope; names are case-sensitive.
type QueueKey struct{ Partition, Account, Region, Name string }

// QueueConfiguration holds typed queue behavior, independently of wire maps.
type QueueConfiguration struct {
	DelaySeconds, MaximumMessageSize, RetentionSeconds, VisibilitySeconds, WaitSeconds int
	FIFO, ContentDeduplication, ManagedSSE                                             bool
	DeduplicationScope, Throughput, Policy, KMSKey                                     string
	KMSReuseSeconds                                                                    int
	PolicyPrincipals                                                                   map[string]string
	DeadLetterTargetARN                                                                string
	MaxReceiveCount                                                                    int
	RedrivePermission                                                                  string
	RedriveSources                                                                     []string
}
type QueueTag struct{ Key, Value string }

// QueueRecord holds queue metadata. Message state is stored separately, so
// listing queues need not load their payloads or receipt histories.
type QueueRecord struct {
	Key                       QueueKey
	ID                        string
	CreationOwner             string
	PolicyOwner               string
	Configuration             QueueConfiguration
	Tags                      []QueueTag
	Created, Modified, Purged time.Time
	Sequence                  uint64
	ManagedEncryptionKey      []byte
	// Metric sampling stops after inactivity. These deadlines do not change
	// the customer-visible LastModifiedTimestamp.
	MetricActiveUntil, NextMetricSample time.Time
}

// MessageRecord stores one encrypted or plaintext message and its delivery state.
type MessageRecord struct {
	ID, Group, DeduplicationID, Sequence, Sender string
	Data                                         []byte
	Encrypted                                    bool
	KMSKeyARN                                    string
	EncryptedDataKey                             []byte
	BodyMD5                                      string
	Sent, FirstReceived, LastReceived, Available time.Time
	// RetentionStarted resets on FIFO dead-letter transfer; Sent remains the
	// original producer timestamp until an explicit redrive creates a message.
	RetentionStarted time.Time
	// AgeStarted excludes initial delay and resets on automatic DLQ transfer,
	// independently of wire timestamps and retention. Zero means an older
	// store lacks the original delay/transfer history, not an age of zero.
	AgeStarted    time.Time
	QueueReceives int
	Receives      int
	LatestReceipt string
	Generation    uint64
	SourceARN     string
}
type ReceiptRecord struct {
	Handle, MessageID, LatestReceipt string
	Expires, Available, LastReceived time.Time
	Generation                       uint64
}
type DeduplicationRecord struct {
	Token, MessageID, Sequence string
	Expires                    time.Time
}
type ReceiveAttemptRecord struct {
	Token               string
	MessageIDs, Handles []string
	Generations         []uint64
	Expires             time.Time
}

// NoisyGroupRecord retains a standard queue tenant's noisy classification until
// its backlog is gone or it has had no in-flight messages for five minutes.
// InFlightUntil is the last delivery's end, including explicit early release.
type NoisyGroupRecord struct {
	Group         string
	InFlightUntil time.Time
}

// QueueMessages groups the records that must transition atomically for FIFO
// ordering, visibility, receipt handles and deduplication. Relational adapters
// should store these typed records in service-owned tables.
type QueueMessages struct {
	Messages       []MessageRecord
	Receipts       []ReceiptRecord
	Deduplications []DeduplicationRecord
	Attempts       []ReceiveAttemptRecord
	NoisyGroups    []NoisyGroupRecord
}

// MoveTaskRecord owns an accepted redrive intent and its next service-time step.
// Due and Moved commit with queue changes; ToMove retains the starting estimate.
// Sequence orders tasks accepted at the same service time. SourceID prevents a
// pending task from consuming a newly created queue with the same ARN.
type MoveTaskRecord struct {
	Handle                        string
	Sequence                      uint64
	Source                        QueueKey
	SourceID, Destination, Status string
	Started, Due                  time.Time
	Rate                          int
	CustomRate                    bool
	Moved, ToMove                 int64
	Failure                       string
	Caller                        awsctx.Metadata
}

// Reader returns detached values from a consistent transaction snapshot.
type Reader interface {
	MetricReader
	// Context carries this snapshot into related repositories. It expires on
	// callback return and must not be retained or used concurrently.
	Context() context.Context
	Queue(QueueKey) (QueueRecord, error)
	Queues() ([]QueueRecord, error)
	Messages(queueID string) (QueueMessages, error)
	DeletedAt(QueueKey) (time.Time, error)
	MoveTasks() ([]MoveTaskRecord, error)
}

// Transaction stages typed writes. Deleting a queue also deletes its message
// records. Implementations must copy caller-owned slices and maps.
type Transaction interface {
	Reader
	MetricWriter
	PutQueue(QueueRecord) error
	PutMessages(queueID string, messages QueueMessages) error
	DeleteQueue(QueueKey) error
	SetDeletedAt(QueueKey, time.Time) error
	PutMoveTask(MoveTaskRecord) error
}

// Repository isolates state from execution. Update is serializable, and every
// write rolls back if the callback, commit, or context fails. Reader/Transaction
// values must not be retained after their callback returns.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt owns one service command. A failed command rolls back its writes
	// without aborting a caller transaction that handles the returned error.
	// Successful writes still commit or roll back with the caller transaction.
	Attempt(context.Context, func(Transaction) error) error
}
