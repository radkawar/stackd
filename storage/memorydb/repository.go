// Package memorydb exports the service-owned typed persistence boundary.
package memorydb

import (
	service "stackd/internal/services/memorydb"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Key              = service.Key
	Cluster          = service.Cluster
	User             = service.User
	ACL              = service.ACL
	ParameterGroup   = service.ParameterGroup
	SubnetGroup      = service.SubnetGroup
	Snapshot         = service.Snapshot
	Subnet           = service.Subnet
	Repository       = service.Repository
	Reader           = service.Reader
	Transaction      = service.Transaction
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(domain) }
