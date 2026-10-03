// Package sesv2 exposes the typed SES repository contract to storage backends.
package sesv2

import (
	service "stackd/internal/services/sesv2"
	"stackd/storage/memory"
)

type Scope = service.Scope
type ResourceKey = service.ResourceKey
type Identity = service.Identity
type Template = service.Template
type ConfigurationSet = service.ConfigurationSet
type Account = service.Account
type Message = service.Message
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return service.NewMemoryRepository(d) }
