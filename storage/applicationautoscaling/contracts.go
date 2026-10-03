// Package applicationautoscaling exposes service-owned scaling storage contracts.
package applicationautoscaling

import (
	domain "stackd/internal/services/applicationautoscaling"
	"stackd/storage/memory"
)

type (
	Repository     = domain.Repository
	Reader         = domain.Reader
	Transaction    = domain.Transaction
	Scope          = domain.Scope
	ListCursor     = domain.ListCursor
	TargetKey      = domain.TargetKey
	TargetRecord   = domain.TargetRecord
	TargetQuery    = domain.TargetQuery
	PolicyKey      = domain.PolicyKey
	PolicyRecord   = domain.PolicyRecord
	PolicyQuery    = domain.PolicyQuery
	ScheduleKey    = domain.ScheduleKey
	ScheduleRecord = domain.ScheduleRecord
	ScheduleQuery  = domain.ScheduleQuery
	ActivityKey    = domain.ActivityKey
	ActivityRecord = domain.ActivityRecord
	ActivityCursor = domain.ActivityCursor
	ActivityQuery  = domain.ActivityQuery
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
