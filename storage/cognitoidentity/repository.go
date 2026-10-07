// Package cognitoidentity exposes service-owned identity-pool persistence contracts.
package cognitoidentity

import (
	domain "stackd/internal/services/cognitoidentity"
	"stackd/storage/memory"
)

type (
	Repository     = domain.Repository
	Reader         = domain.Reader
	Transaction    = domain.Transaction
	Scope          = domain.Scope
	PoolKey        = domain.PoolKey
	PoolRecord     = domain.PoolRecord
	IdentityRecord = domain.IdentityRecord
	Login          = domain.Login
	ResourceOwner  = domain.ResourceOwner
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
