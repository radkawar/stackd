// Package firehose owns delivery-stream commands and retained destination work.
package firehose

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/scheduler"
)

var ErrNotFound = errors.New("firehose resource not found")

type Scope struct{ Partition, AccountID, Region string }

type StreamKey struct {
	Scope
	Name string
}

func (k StreamKey) ARN() string {
	return "arn:" + k.Partition + ":firehose:" + k.Region + ":" + k.AccountID + ":deliverystream/" + k.Name
}

// StreamRecord owns one incarnation. Destination is the authoritative S3
// configuration; both public S3 descriptions are views of this same value.
// BufferID identifies the still-open buffer, not a prepared delivery attempt.
type StreamRecord struct {
	Key          StreamKey
	ID           string
	Status       string
	Version      int64
	Created      time.Time
	Updated      *time.Time
	LifecycleDue time.Time
	Destination  api.ExtendedS3DestinationDescription
	Tags         map[string]string
	Source       *KinesisSourceRecord
	BufferID     string
}

type StreamQuery struct {
	Scope Scope
	Type  string
	After string
	Limit int
}

// KinesisSourceRecord retains the source incarnation and the delivery boundary.
// Source permission failures delay polling; they do not replace the source or
// advance its checkpoints.
type KinesisSourceRecord struct {
	ARN, RoleARN                string
	Created, DeliveryStart, Due time.Time
	RetentionHours              int32
}

type CheckpointKey struct{ StreamID, ShardID string }

type CheckpointRecord struct {
	Key      CheckpointKey
	Sequence string
	Closed   bool
}

// BufferKind distinguishes admitted input from the independent S3 obligations
// produced by transformation. Only input buffers follow destination updates.
type BufferKind string

const (
	BufferInput               BufferKind = ""
	BufferPrimary             BufferKind = "primary"
	BufferBackup              BufferKind = "backup"
	BufferFailed              BufferKind = "failed"
	BufferDecompressionFailed BufferKind = "decompression-failed"
)

// BufferRecord retains accepted bytes until delivery succeeds or retention ends.
// Prepared work snapshots its configuration and version; ObjectKey is fixed
// when S3 delivery starts. Retries cannot silently switch destinations.
type BufferRecord struct {
	ID, StreamID  string
	Kind          BufferKind
	Stream        StreamKey
	Created, Due  time.Time
	Count, Bytes  int64
	ParentEventID string
	ObjectKey     string
	StreamVersion int64
	Configuration *api.ExtendedS3DestinationDescription
}

type RecordKey struct {
	BufferID string
	Position int64
}

type RecordRecord struct {
	Key           RecordKey
	Data          []byte
	Arrived       time.Time
	OriginalBytes int64
	Kinesis       *KinesisRecordMetadata
}

// KinesisRecordMetadata preserves source identity for the transformation
// envelope. Its arrival timestamp is RecordRecord.Arrived, not another clock.
type KinesisRecordMetadata struct {
	ShardID, PartitionKey, SequenceNumber string
	SubsequenceNumber                     int64
}

type ProcessingState string

const (
	ProcessingQueued   ProcessingState = "queued"
	ProcessingInFlight ProcessingState = "in-flight"
)

// ProcessingRecord owns a claim on an immutable input buffer. Attempts also
// distinguish a completing invocation from a later retry after recovery.
type ProcessingRecord struct {
	BufferID string
	State    ProcessingState
	Attempts int32
	Due      time.Time
}

type MetricPublicationKey struct {
	Stream StreamKey
	Minute time.Time
}

type MetricSample struct {
	Name        string
	Value       float64
	SampleCount int64
}

// Repository joins the callback's shared transaction domain. Destination writes
// and Kinesis record reads run outside callbacks; accepted records, checkpoints,
// metrics and API events commit with the state transition that owns them.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

type Reader interface {
	Context() context.Context
	Stream(StreamKey) (StreamRecord, error)
	StreamByID(string) (StreamRecord, error)
	Streams(StreamQuery) ([]StreamRecord, error)
	NextLifecycle() (StreamRecord, error)
	Buffer(string) (BufferRecord, error)
	OpenOutputBuffer(streamID string, version int64, kind BufferKind) (BufferRecord, error)
	Records(string) ([]RecordRecord, error)
	NextDelivery() (BufferRecord, error)
	Processing(string) (ProcessingRecord, error)
	NextProcessing() (ProcessingRecord, error)
	InFlightProcessing() ([]ProcessingRecord, error)
	NextSource() (StreamRecord, error)
	Checkpoints(string) ([]CheckpointRecord, error)
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type Transaction interface {
	Reader
	PutStream(StreamRecord) error
	// DeleteStream removes only this incarnation and its records/checkpoints.
	// Already-retained CloudWatch samples survive resource deletion.
	DeleteStream(StreamKey) error
	PutBuffer(BufferRecord) error
	PutRecord(RecordRecord) error
	// DeleteBuffer removes all of its record bytes.
	DeleteBuffer(string) error
	PutCheckpoint(CheckpointRecord) error
	PutProcessing(ProcessingRecord) error
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}

func streamJob(v StreamRecord, due time.Time) scheduler.Job {
	return scheduler.Job{Key: v.ID, Version: uint64(v.Version), Due: due}
}
