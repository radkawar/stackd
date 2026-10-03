// Package elbv2 exports the ALB service persistence boundary.
package elbv2

import (
	service "stackd/internal/services/elbv2"
	"stackd/storage/memory"
)

type (
	Scope                = service.Scope
	LoadBalancerRecord   = service.LoadBalancerRecord
	TargetGroupRecord    = service.TargetGroupRecord
	ListenerRecord       = service.ListenerRecord
	RuleRecord           = service.RuleRecord
	TargetRecord         = service.TargetRecord
	MetricPublicationKey = service.MetricPublicationKey
	MetricSample         = service.MetricSample
	Repository           = service.Repository
	Reader               = service.Reader
	Transaction          = service.Transaction
	MemoryRepository     = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
