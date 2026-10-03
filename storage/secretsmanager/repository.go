// Package secretsmanager exposes service-owned Secrets Manager storage contracts.
package secretsmanager

import (
	domain "stackd/internal/services/secretsmanager"
	"stackd/storage/memory"
)

type (
	Repository     = domain.Repository
	Reader         = domain.Reader
	Transaction    = domain.Transaction
	Scope          = domain.Scope
	SecretKey      = domain.SecretKey
	VersionKey     = domain.VersionKey
	SecretRecord   = domain.SecretRecord
	SealedValue    = domain.SealedValue
	VersionRecord  = domain.VersionRecord
	ReplicaKey     = domain.ReplicaKey
	ReplicaRecord  = domain.ReplicaRecord
	RotationRecord = domain.RotationRecord
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
