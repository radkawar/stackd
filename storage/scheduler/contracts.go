// Package scheduler exposes service-owned Scheduler storage contracts.
package scheduler

import (
	domain "stackd/internal/services/scheduler"
	"stackd/storage/memory"
)

type (
	Repository          = domain.Repository
	Reader              = domain.Reader
	Transaction         = domain.Transaction
	Scope               = domain.Scope
	GroupKey            = domain.GroupKey
	ScheduleKey         = domain.ScheduleKey
	GroupRecord         = domain.GroupRecord
	ScheduleRecord      = domain.ScheduleRecord
	TargetRecord        = domain.TargetRecord
	DeliveryRecord      = domain.DeliveryRecord
	ECSTarget           = domain.ECSTarget
	CapacityProvider    = domain.CapacityProvider
	PlacementConstraint = domain.PlacementConstraint
	PlacementStrategy   = domain.PlacementStrategy
	Tag                 = domain.Tag
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository {
	return domain.NewMemoryRepository(d)
}
