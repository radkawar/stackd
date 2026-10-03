// Package sqs exposes the typed SQS storage contract for backend implementations.
// Aliases preserve the service's domain types without duplicating their schemas.
package sqs

import (
	"stackd/internal/awsctx"
	domain "stackd/internal/services/sqs"
	"stackd/storage/memory"
)

// Storage contracts and records retain the service-defined transaction and
// ownership rules. See the aliased types for their full documentation.
type (
	Repository           = domain.Repository
	Reader               = domain.Reader
	Transaction          = domain.Transaction
	QueueKey             = domain.QueueKey
	QueueConfiguration   = domain.QueueConfiguration
	QueueTag             = domain.QueueTag
	QueueRecord          = domain.QueueRecord
	MessageRecord        = domain.MessageRecord
	ReceiptRecord        = domain.ReceiptRecord
	DeduplicationRecord  = domain.DeduplicationRecord
	ReceiveAttemptRecord = domain.ReceiveAttemptRecord
	NoisyGroupRecord     = domain.NoisyGroupRecord
	QueueMessages        = domain.QueueMessages
	MoveTaskRecord       = domain.MoveTaskRecord
	MetricPublicationKey = domain.MetricPublicationKey
	MetricSample         = domain.MetricSample
	MetricReader         = domain.MetricReader
	MetricWriter         = domain.MetricWriter
)

// NewMemory joins transactionDomain; nil constructs an independent domain.
func NewMemory(transactionDomain *memory.Domain) Repository {
	return domain.NewMemoryRepository(transactionDomain)
}

var ErrNotFound = domain.ErrNotFound

// CallerMetadata is the verified caller snapshot persisted with redrive tasks.
type CallerMetadata = awsctx.Metadata
