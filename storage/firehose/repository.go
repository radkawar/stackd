// Package firehose exposes service-owned Firehose storage contracts.
package firehose

import (
	domain "stackd/internal/services/firehose"
	"stackd/storage/memory"
)

type (
	Repository            = domain.Repository
	Reader                = domain.Reader
	Transaction           = domain.Transaction
	Scope                 = domain.Scope
	StreamKey             = domain.StreamKey
	StreamRecord          = domain.StreamRecord
	StreamQuery           = domain.StreamQuery
	KinesisSourceRecord   = domain.KinesisSourceRecord
	CheckpointKey         = domain.CheckpointKey
	CheckpointRecord      = domain.CheckpointRecord
	BufferKind            = domain.BufferKind
	BufferRecord          = domain.BufferRecord
	RecordKey             = domain.RecordKey
	RecordRecord          = domain.RecordRecord
	KinesisRecordMetadata = domain.KinesisRecordMetadata
	ProcessingState       = domain.ProcessingState
	ProcessingRecord      = domain.ProcessingRecord
	MetricPublicationKey  = domain.MetricPublicationKey
	MetricSample          = domain.MetricSample
)

const (
	BufferInput               = domain.BufferInput
	BufferPrimary             = domain.BufferPrimary
	BufferBackup              = domain.BufferBackup
	BufferFailed              = domain.BufferFailed
	BufferDecompressionFailed = domain.BufferDecompressionFailed
	ProcessingQueued          = domain.ProcessingQueued
	ProcessingInFlight        = domain.ProcessingInFlight
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
