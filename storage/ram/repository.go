// Package ram exposes typed RAM state for replaceable storage backends.
package ram

import (
	service "stackd/internal/services/ram"
	"stackd/storage/memory"
)

type Scope = service.Scope
type ResourceIdentity = service.ResourceIdentity
type Share = service.Share
type ResourceAssociation = service.ResourceAssociation
type PrincipalAssociation = service.PrincipalAssociation
type PermissionAssociation = service.PermissionAssociation
type Invitation = service.Invitation
type Permission = service.Permission
type PermissionVersion = service.PermissionVersion
type Receipt = service.Receipt
type Replacement = service.Replacement
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) Repository { return service.NewMemoryRepository(domain) }
