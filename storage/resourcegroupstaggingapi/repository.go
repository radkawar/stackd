// Package resourcegroupstaggingapi exposes the typed inventory membership store.
package resourcegroupstaggingapi

import (
	domain "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/storage/memory"
)

type (
	Scope       = domain.Scope
	Membership  = domain.Membership
	Report      = domain.Report
	Reader      = domain.Reader
	Transaction = domain.Transaction
	Repository  = domain.Repository
)

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
