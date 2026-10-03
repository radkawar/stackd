// Package dynamodb exposes service-owned control and retained stream storage.
// Item storage belongs to the injected external runtime.
package dynamodb

import (
	domain "stackd/internal/services/dynamodb"
	"stackd/storage/memory"
)

type (
	Repository              = domain.Repository
	Reader                  = domain.Reader
	Transaction             = domain.Transaction
	Scope                   = domain.Scope
	TableKey                = domain.TableKey
	DatabaseRecord          = domain.DatabaseRecord
	TableRecord             = domain.TableRecord
	TableQuery              = domain.TableQuery
	BackupKey               = domain.BackupKey
	BackupRecord            = domain.BackupRecord
	BackupQuery             = domain.BackupQuery
	RecoveryRecord          = domain.RecoveryRecord
	RecoveryChange          = domain.RecoveryChange
	RecoveryChangeQuery     = domain.RecoveryChangeQuery
	WriteConsumers          = domain.WriteConsumers
	MutationCapture         = domain.MutationCapture
	MutationSource          = domain.MutationSource
	MutationItem            = domain.MutationItem
	KinesisDestination      = domain.KinesisDestination
	KinesisConsumer         = domain.KinesisConsumer
	KinesisDelivery         = domain.KinesisDelivery
	ReplicaState            = domain.ReplicaState
	ReplicaBootstrap        = domain.ReplicaBootstrap
	ReplicaChange           = domain.ReplicaChange
	TagRecord               = domain.TagRecord
	PolicyKey               = domain.PolicyKey
	PolicyRecord            = domain.PolicyRecord
	StreamGeneration        = domain.StreamGeneration
	StreamShard             = domain.StreamShard
	StreamEntry             = domain.StreamEntry
	StreamEntryQuery        = domain.StreamEntryQuery
	TTLDeletion             = domain.TTLDeletion
	MetricPublicationKey    = domain.MetricPublicationKey
	MetricSample            = domain.MetricSample
	TransactionCapacityKey  = domain.TransactionCapacityKey
	TransactionCapacity     = domain.TransactionCapacity
	TransactionReadCapacity = domain.TransactionReadCapacity
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
