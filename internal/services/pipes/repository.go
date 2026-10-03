// Package pipes owns EventBridge Pipes controls and retained source work.
package pipes

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/pipes"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
	"time"
)

var ErrNotFound = errors.New("pipe not found")

type Scope struct {
	Partition, AccountID, Region string
}
type Key struct {
	Scope
	Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":pipes:" + k.Region + ":" + k.AccountID + ":pipe/" + k.Name
}

// SourceSettings is the authoritative source configuration. Checkpoints and
// received records are separate rows, never embedded in the resource document.
type SourceSettings struct {
	Kind, StartingPosition                                            string
	StartingTime                                                      *time.Time
	BatchSize, WindowSeconds, MaximumAge, MaximumRetries, Parallelism int32
	AutomaticBisect                                                   bool
	DLQ                                                               string
	Filters                                                           []string
	Kafka                                                             KafkaSettings
}
type PipeRecord struct {
	Key                                                       Key
	ID                                                        string
	Version                                                   int64
	Description, RoleARN, SourceARN, TargetARN, EnrichmentARN string
	State, Desired, Reason                                    string
	Created, Modified, Due                                    time.Time
	Source                                                    SourceSettings
	EnrichmentTemplate                                        string
	EnrichmentHTTP                                            *api.PipeEnrichmentHttpParameters
	Target                                                    api.PipeTargetParameters
	Tags                                                      api.TagMap
	ParentEventID                                             string
	KMSKeyARN                                                 string
	Encrypted                                                 *EncryptedConfiguration
	Logging                                                   Logging
}

// EncryptedConfiguration owns only the sensitive event patterns and templates.
// KMS-wrapped data keys and authenticated ciphertext are safe to persist.
type EncryptedConfiguration struct {
	WrappedKey, Nonce, Ciphertext []byte
}
type Logging struct {
	Level                                                                   string
	IncludeExecutionData                                                    bool
	LogGroupARN, FirehoseARN, BucketName, BucketOwner, Prefix, OutputFormat string
}
type Keys interface {
	Generate(context.Context, PipeRecord, string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, PipeRecord, []byte) ([]byte, *awswire.Error)
}
type ExecutionLog struct {
	ID, Stage, Level, Error string
	At                      time.Time
	Duration                time.Duration
	Payload                 []byte
}
type Diagnostics interface {
	Validate(context.Context, PipeRecord) *awswire.Error
	Publish(context.Context, PipeRecord, ExecutionLog) error
}
type Checkpoint struct {
	PipeID, ShardID, ParentID, AdjacentParentID, Sequence, Iterator string
	Initialized, Closed                                             bool
}

// Work keeps accepted source bytes and delivery progress. Acknowledgment is a
// distinct phase so a target success is never repeated merely because Delete
// failed. Stream ordering follows each shard's monotonically increasing ordinal.
type Work struct {
	ID, PipeID, ShardID, RecordID, Sequence, Receipt, GroupID string
	Ordinal                                                   int64
	Event                                                     []byte
	Created, Due                                              time.Time
	Attempts                                                  int32
	BatchLimit                                                int32
	Phase                                                     string
	Filtered                                                  bool
	LastError                                                 string
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Pipe(Key) (PipeRecord, error)
	PipeByID(string) (PipeRecord, error)
	Pipes() ([]PipeRecord, error)
	Checkpoints(string) ([]Checkpoint, error)
	Work(string) ([]Work, error)
	KafkaIdentity(string) (KafkaIdentity, error)
}
type Transaction interface {
	Reader
	PutPipe(PipeRecord) error
	DeletePipe(Key) error
	PutCheckpoint(Checkpoint) error
	PutWork(Work) error
	DeleteWork(string) error
	PutKafkaIdentity(string, KafkaIdentity) error
}

// Source consumers reuse the source-owner contracts, not Lambda ownership or
// identity. Implementations assume the Pipes role and reauthorize each command.
type Sources interface {
	SQS(context.Context, PipeRecord) (lambda.SQSConsumer, *awswire.Error)
	Kinesis(context.Context, PipeRecord) (lambda.KinesisConsumer, *awswire.Error)
	DynamoDB(context.Context, PipeRecord) (lambda.DynamoDBConsumer, *awswire.Error)
}
type DeliveryResult struct {
	FailedIDs []string
}

// TargetEvent retains the pre-transform input for dynamic target parameters;
// Payload is the independently transformed body sent to the destination.
type TargetEvent struct {
	Input, Payload []byte
}
type Targets interface {
	Validate(context.Context, PipeRecord) *awswire.Error
	Enrich(context.Context, PipeRecord, []TargetEvent) ([]byte, *awswire.Error)
	Deliver(context.Context, PipeRecord, []Work, []TargetEvent, bool) (DeliveryResult, *awswire.Error)
}
