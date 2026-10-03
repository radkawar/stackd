// Package account exposes Account Management's typed storage contract.
package account

import (
	domain "stackd/internal/services/account"
	"stackd/storage/memory"
)

type (
	Repository          = domain.Repository
	Reader              = domain.Reader
	Writer              = domain.Writer
	RegionKey           = domain.RegionKey
	RegionRecord        = domain.RegionRecord
	RegionStatus        = domain.RegionStatus
	Scope               = domain.Scope
	ContactInformation  = domain.ContactInformation
	PrimaryEmailUpdate  = domain.PrimaryEmailUpdate
	PrimaryEmailStatus  = domain.PrimaryEmailStatus
	ContactType         = domain.ContactType
	AlternateContact    = domain.AlternateContact
	AlternateContactKey = domain.AlternateContactKey
)

// NewMemory constructs a backend in the shared identity transaction domain.
func NewMemory(transactionDomain *memory.Domain) Repository {
	return domain.NewMemoryRepository(transactionDomain)
}
