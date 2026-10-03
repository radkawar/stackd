// Package docdb exports the service-owned typed DocumentDB persistence boundary.
package docdb

import (
	service "stackd/internal/services/docdb"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Key              = service.Key
	Cluster          = service.Cluster
	Instance         = service.Instance
	Snapshot         = service.Snapshot
	Repository       = service.Repository
	Reader           = service.Reader
	Transaction      = service.Transaction
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(domain) }
