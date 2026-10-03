// Package pipes exposes the service-owned typed Pipes repository.
package pipes

import (
	domain "stackd/internal/services/pipes"
	"stackd/storage/memory"
)

type (
	Repository             = domain.Repository
	Reader                 = domain.Reader
	Transaction            = domain.Transaction
	Scope                  = domain.Scope
	Key                    = domain.Key
	PipeRecord             = domain.PipeRecord
	SourceSettings         = domain.SourceSettings
	Checkpoint             = domain.Checkpoint
	Work                   = domain.Work
	KafkaIdentity          = domain.KafkaIdentity
	EncryptedConfiguration = domain.EncryptedConfiguration
	Logging                = domain.Logging
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository {
	return domain.NewMemoryRepository(d)
}
func Stored(p PipeRecord) PipeRecord {
	return domain.Stored(p)
}
