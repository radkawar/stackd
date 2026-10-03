// Package glue exposes the service-owned Glue storage contract.
package glue

import (
	domain "stackd/internal/services/glue"
	"stackd/storage/memory"
)

type Repository = domain.Repository
type Reader = domain.Reader
type Transaction = domain.Transaction
type Scope = domain.Scope
type ResourceKey = domain.ResourceKey
type CatalogKey = domain.CatalogKey
type DatabaseKey = domain.DatabaseKey
type TableKey = domain.TableKey
type PartitionKey = domain.PartitionKey
type FunctionKey = domain.FunctionKey
type CatalogRecord = domain.CatalogRecord
type DatabaseRecord = domain.DatabaseRecord
type TableRecord = domain.TableRecord
type PartitionRecord = domain.PartitionRecord
type FunctionRecord = domain.FunctionRecord

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
