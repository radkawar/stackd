// Package athena exports the service-owned typed persistence boundary.
package athena

import (
	service "stackd/internal/services/athena"
	"stackd/storage/memory"
)

type Scope = service.Scope
type ResourceKey = service.ResourceKey
type StatementKey = service.StatementKey
type WorkGroupRecord = service.WorkGroupRecord
type CatalogRecord = service.CatalogRecord
type NamedQueryRecord = service.NamedQueryRecord
type PreparedStatementRecord = service.PreparedStatementRecord
type QueryRecord = service.QueryRecord
type ResourceQuery = service.ResourceQuery
type Repository = service.Repository
type Reader = service.Reader
type Transaction = service.Transaction
type MemoryRepository = service.MemoryRepository

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(domain) }
