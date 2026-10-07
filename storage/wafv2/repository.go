// Package wafv2 exposes typed AWS WAF web ACL, IP set and association persistence.
package wafv2

import (
	service "stackd/internal/services/wafv2"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Definition       = service.Definition
	WebACL           = service.WebACL
	IPSet            = service.IPSet
	ResourceOwner    = service.ResourceOwner
	AssociationOwner = service.AssociationOwner
	Association      = service.Association
	MetricKey        = service.MetricKey
	MetricSample     = service.MetricSample
	SampledRequest   = service.SampledRequest
	Reader           = service.Reader
	Transaction      = service.Transaction
	Repository       = service.Repository
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
