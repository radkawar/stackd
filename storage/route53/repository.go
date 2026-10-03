// Package route53 exposes the hosted-zone storage contract.
package route53

import (
	service "stackd/internal/services/route53"
	"stackd/storage/memory"
)

type Scope = service.Scope
type AliasTarget = service.AliasTarget
type RecordSet = service.RecordSet
type Zone = service.Zone
type Change = service.Change
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) Repository { return service.NewMemoryRepository(domain) }
