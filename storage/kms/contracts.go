// Package kms exposes the typed KMS storage contract for backend implementations.
// Aliases preserve the service's domain types without duplicating their schemas.
package kms

import (
	domain "stackd/internal/services/kms"
	"stackd/storage/memory"
)

// Storage contracts and records retain the service-defined transaction and
// ownership rules. See the aliased types for their full documentation.
type (
	Storage                = domain.Storage
	Reader                 = domain.Reader
	Transaction            = domain.Transaction
	StorageScope           = domain.StorageScope
	KeyOwner               = domain.KeyOwner
	KeySetRecord           = domain.KeySetRecord
	KeyRecord              = domain.KeyRecord
	KeyMaterialRecord      = domain.KeyMaterialRecord
	ImportedMaterialRecord = domain.ImportedMaterialRecord
	ImportParametersRecord = domain.ImportParametersRecord
	RotationState          = domain.RotationState
	PrincipalBinding       = domain.PrincipalBinding
	TagRecord              = domain.TagRecord
	GrantRecord            = domain.GrantRecord
	AliasOwner             = domain.AliasOwner
	AliasRecord            = domain.AliasRecord
)

var ErrKeySetNotFound = domain.ErrKeySetNotFound

// NewMemory joins transactionDomain; nil constructs an independent domain.
func NewMemory(transactionDomain *memory.Domain) Storage {
	return domain.NewMemoryStorage(transactionDomain)
}
