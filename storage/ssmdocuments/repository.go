// Package ssmdocuments exposes service-owned immutable Command document storage.
package ssmdocuments

import (
	domain "stackd/internal/services/ssmdocuments"
	"stackd/storage/memory"
)

type (
	Repository  = domain.Repository
	Reader      = domain.Reader
	Transaction = domain.Transaction
	Scope       = domain.Scope
	Key         = domain.Key
	VersionKey  = domain.VersionKey
	Record      = domain.Record
	Version     = domain.Version
	Activation  = domain.Activation
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
