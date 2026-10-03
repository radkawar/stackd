// Package autoscaling exposes the service-owned EC2 Auto Scaling storage contract.
package autoscaling

import (
	domain "stackd/internal/services/autoscaling"
	"stackd/storage/memory"
)

type (
	Repository      = domain.Repository
	Reader          = domain.Reader
	Transaction     = domain.Transaction
	Scope           = domain.Scope
	GroupKey        = domain.GroupKey
	GroupRecord     = domain.GroupRecord
	GroupQuery      = domain.GroupQuery
	GroupWork       = domain.GroupWork
	InstanceRecord  = domain.InstanceRecord
	ActivityKey     = domain.ActivityKey
	ActivityRecord  = domain.ActivityRecord
	PolicyKey       = domain.PolicyKey
	PolicyRecord    = domain.PolicyRecord
	ScheduleKey     = domain.ScheduleKey
	ScheduleRecord  = domain.ScheduleRecord
	HookKey         = domain.HookKey
	HookRecord      = domain.HookRecord
	LifecycleAction = domain.LifecycleAction
	RefreshRecord   = domain.RefreshRecord
	RefreshMember   = domain.RefreshMember
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
