// Package eks exposes service-owned EKS storage contracts.
package eks

import (
	domain "stackd/internal/services/eks"
	"stackd/storage/memory"
)

type (
	Repository                = domain.Repository
	Reader                    = domain.Reader
	Transaction               = domain.Transaction
	Scope                     = domain.Scope
	Key                       = domain.Key
	Cluster                   = domain.Cluster
	AccessEntry               = domain.AccessEntry
	AccessPolicy              = domain.AccessPolicy
	AccessMutation            = domain.AccessMutation
	Update                    = domain.Update
	CloudFormationCreationKey = domain.CloudFormationCreationKey
	CloudFormationCreation    = domain.CloudFormationCreation
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
