package autoscaling

import (
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
	"time"
)

func (r reader) lifecycleAction(row sqlcgen.AsgLifecycleAction) (domain.LifecycleAction, error) {
	out := domain.LifecycleAction{
		Group:            groupKey(row.Partition, row.AccountID, row.Region, row.GroupName),
		Token:            row.Token,
		GroupID:          row.GroupID,
		HookName:         row.HookName,
		InstanceID:       row.InstanceID,
		Transition:       row.Transition,
		DefaultResult:    row.DefaultResult,
		HeartbeatTimeout: time.Duration(row.HeartbeatTimeout),
		Deadline:         row.Deadline.Time,
		GlobalDeadline:   row.GlobalDeadline.Time,
		OriginEventID:    row.OriginEventID,
	}

	return out, nil
}

func (w writer) PutLifecycleAction(v domain.LifecycleAction) error {
	p := sqlcgen.PutLifecycleActionParams{
		Partition:        v.Group.Partition,
		AccountID:        v.Group.AccountID,
		Region:           v.Group.Region,
		GroupName:        v.Group.Name,
		Token:            v.Token,
		GroupID:          v.GroupID,
		HookName:         v.HookName,
		InstanceID:       v.InstanceID,
		Transition:       v.Transition,
		DefaultResult:    v.DefaultResult,
		HeartbeatTimeout: int64(v.HeartbeatTimeout),
		Deadline:         deadline(v.Deadline),
		GlobalDeadline:   deadline(v.GlobalDeadline),
		OriginEventID:    v.OriginEventID,
	}

	return w.q.PutLifecycleAction(w.ctx, p)
}
