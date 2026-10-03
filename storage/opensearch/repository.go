// Package opensearch exports the service-owned typed persistence boundary.
package opensearch

import (
	service "stackd/internal/services/opensearch"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Key              = service.Key
	Domain           = service.Domain
	Repository       = service.Repository
	Reader           = service.Reader
	Transaction      = service.Transaction
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) *MemoryRepository {
	return service.NewMemoryRepository(domain)
}
