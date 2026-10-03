// Package elasticache exports the service-owned persistence contract.
package elasticache

import (
	service "stackd/internal/services/elasticache"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Key              = service.Key
	Cluster          = service.Cluster
	Snapshot         = service.Snapshot
	User             = service.User
	UserGroup        = service.UserGroup
	ParameterGroup   = service.ParameterGroup
	SubnetGroup      = service.SubnetGroup
	Subnet           = service.Subnet
	Repository       = service.Repository
	Reader           = service.Reader
	Transaction      = service.Transaction
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
