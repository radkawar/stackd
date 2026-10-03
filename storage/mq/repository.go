// Package mq exposes the service-owned typed broker persistence boundary.
package mq

import (
	service "stackd/internal/services/mq"
	"stackd/storage/memory"
)

type (
	Scope                       = service.Scope
	BrokerRecord                = service.BrokerRecord
	Endpoint                    = service.Endpoint
	LogSettings                 = service.LogSettings
	LogCursor                   = service.LogCursor
	UserRecord                  = service.UserRecord
	ConfigurationReference      = service.ConfigurationReference
	ConfigurationRevisionRecord = service.ConfigurationRevisionRecord
	ConfigurationRecord         = service.ConfigurationRecord
	Repository                  = service.Repository
	Reader                      = service.Reader
	Transaction                 = service.Transaction
	MemoryRepository            = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
