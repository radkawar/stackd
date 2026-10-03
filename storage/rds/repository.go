// Package rds exports the service-owned typed persistence boundary.
package rds

import (
	service "stackd/internal/services/rds"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Key              = service.Key
	Database         = service.Database
	Snapshot         = service.Snapshot
	ParameterGroup   = service.ParameterGroup
	Subnet           = service.Subnet
	SubnetGroup      = service.SubnetGroup
	Repository       = service.Repository
	Reader           = service.Reader
	Transaction      = service.Transaction
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) *MemoryRepository {
	return service.NewMemoryRepository(domain)
}
