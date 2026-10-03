// Package identitycenter exposes typed IAM Identity Center state for replaceable storage backends.
package identitycenter

import (
	service "stackd/internal/services/identitycenter"
	"stackd/storage/memory"
)

type Scope = service.Scope
type Instance = service.Instance
type PolicyReference = service.PolicyReference
type PermissionSet = service.PermissionSet
type Assignment = service.Assignment
type Provisioning = service.Provisioning
type Operation = service.Operation
type Client = service.Client
type Device = service.Device
type Authorization = service.Authorization
type Session = service.Session
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) Repository { return service.NewMemoryRepository(domain) }
