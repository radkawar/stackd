// Package ecr exposes private-registry storage contracts.
package ecr

import (
	domain "stackd/internal/services/ecr"
	"stackd/storage/memory"
)

type (
	Repository        = domain.Repository
	Reader            = domain.Reader
	Transaction       = domain.Transaction
	Scope             = domain.Scope
	RepositoryKey     = domain.RepositoryKey
	ImageKey          = domain.ImageKey
	UploadKey         = domain.UploadKey
	RepositoryRecord  = domain.RepositoryRecord
	RegistryRecord    = domain.RegistryRecord
	ImageRecord       = domain.ImageRecord
	BlobRecord        = domain.BlobRecord
	UploadRecord      = domain.UploadRecord
	ReplicationKey    = domain.ReplicationKey
	ReplicationRecord = domain.ReplicationRecord
	TokenRecord       = domain.TokenRecord
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
