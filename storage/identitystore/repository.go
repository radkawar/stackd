// Package identitystore exposes the typed directory repository to storage backends.
package identitystore

import (
	service "stackd/internal/services/identitystore"
	"stackd/storage/memory"
)

type Scope = service.Scope
type Store = service.Store
type Key = service.Key
type Name = service.Name
type Email = service.Email
type User = service.User
type Group = service.Group
type Membership = service.Membership
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return service.NewMemoryRepository(d) }
