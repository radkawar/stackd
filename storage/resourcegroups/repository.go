// Package resourcegroups exposes typed resource group storage.
package resourcegroups

import (
	domain "stackd/internal/services/resourcegroups"
	"stackd/storage/memory"
)

type (
	Scope             = domain.Scope
	Group             = domain.Group
	Grouping          = domain.Grouping
	TagSyncTask       = domain.TagSyncTask
	AppliedMembership = domain.AppliedMembership
	LifecycleAccount  = domain.LifecycleAccount
	LifecycleSnapshot = domain.LifecycleSnapshot
	LifecycleMember   = domain.LifecycleMember
	Reader            = domain.Reader
	Transaction       = domain.Transaction
	Repository        = domain.Repository
)

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
