// Package organizations exposes the typed Organizations storage contract for backend implementations.
// Aliases preserve the service's domain types without duplicating their schemas.
package organizations

import (
	domain "stackd/internal/services/organizations"
	"stackd/storage/memory"
)

// Storage contracts and records retain the service-defined transaction and
// ownership rules. See the aliased types for their full documentation.
type (
	Storage               = domain.Storage
	OrganizationDetails   = domain.OrganizationDetails
	RootRecord            = domain.RootRecord
	AccountRecord         = domain.AccountRecord
	UnitRecord            = domain.UnitRecord
	AccountCreationRecord = domain.AccountCreationRecord
	HandshakeRecord       = domain.HandshakeRecord
	PolicyRecord          = domain.PolicyRecord
	ResourcePolicyRecord  = domain.ResourcePolicyRecord
	PolicyTypeRecord      = domain.PolicyTypeRecord
	PolicySummaryRecord   = domain.PolicySummaryRecord
	ParentRecord          = domain.ParentRecord
	PolicyAttachment      = domain.PolicyAttachment
	EffectivePolicyRecord = domain.EffectivePolicyRecord
	EffectivePolicyError  = domain.EffectivePolicyError
	ResourceTagRecord     = domain.ResourceTagRecord
	ServiceAccessRecord   = domain.ServiceAccessRecord
	DelegationRecord      = domain.DelegationRecord
	OrganizationRecord    = domain.OrganizationRecord
	RootAccessFeatures    = domain.RootAccessFeatures
	PartitionRecord       = domain.PartitionRecord
)

// NewMemory constructs an empty backend using the shared memory transaction engine.
func NewMemory(transactionDomain *memory.Domain) Storage {
	return domain.NewMemoryStorage(transactionDomain)
}
