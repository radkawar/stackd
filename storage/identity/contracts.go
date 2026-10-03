// Package identity exposes the typed Identity storage contract for backend implementations.
// Aliases preserve the service's domain types without duplicating their schemas.
package identity

import domain "stackd/internal/identity"

// Storage contracts and records retain the service-defined transaction and
// ownership rules. See the aliased types for their full documentation.
type (
	Repository  = domain.Repository
	Reader      = domain.Reader
	Transaction = domain.Transaction
	Record      = domain.Record
	Credential  = domain.Credential
	Principal   = domain.Principal
	SessionType = domain.SessionType
	Status      = domain.Status
	LastUsed    = domain.LastUsed
)

// NewMemory constructs an empty backend using the shared memory transaction engine.
func NewMemory() Repository { return domain.NewMemoryRepository() }

var ErrNotFound = domain.ErrNotFound

const (
	Active                     = domain.Active
	Inactive                   = domain.Inactive
	SessionTypeGetSessionToken = domain.SessionTypeGetSessionToken
	SessionTypeAssumeRole      = domain.SessionTypeAssumeRole
	SessionTypeFederation      = domain.SessionTypeFederation
)
