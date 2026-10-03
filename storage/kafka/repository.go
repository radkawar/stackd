// Package kafka exports the service-owned typed MSK persistence boundary.
package kafka

import (
	service "stackd/internal/services/kafka"
	"stackd/storage/memory"
)

type (
	Scope               = service.Scope
	ClusterRecord       = service.ClusterRecord
	ConfigurationRecord = service.ConfigurationRecord
	RevisionRecord      = service.RevisionRecord
	OperationRecord     = service.OperationRecord
	Repository          = service.Repository
	Reader              = service.Reader
	Transaction         = service.Transaction
	MemoryRepository    = service.MemoryRepository
	Endpoint            = service.Endpoint
	Broker              = service.Broker
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
