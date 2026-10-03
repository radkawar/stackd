package autoscaling

import (
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
	"time"
)

func (r reader) Group(key domain.GroupKey) (domain.GroupRecord, error) {
	row, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if err != nil {
		return domain.GroupRecord{}, missing(err)
	}
	return r.group(row)
}

func (w writer) DeleteGroup(key domain.GroupKey) error {
	// Companion rows are independently writable, matching the memory owner.
	// Public activity history intentionally survives every group incarnation.
	if err := w.q.DeleteGroupInstances(w.ctx, sqlcgen.DeleteGroupInstancesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupPolicies(w.ctx, sqlcgen.DeleteGroupPoliciesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupSchedules(w.ctx, sqlcgen.DeleteGroupSchedulesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupHooks(w.ctx, sqlcgen.DeleteGroupHooksParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupLifecycleActions(w.ctx, sqlcgen.DeleteGroupLifecycleActionsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name}); err != nil {
		return err
	}
	return w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}

func (r reader) Instance(scope domain.Scope, id string) (domain.InstanceRecord, error) {
	row, err := r.q.GetInstance(r.ctx, sqlcgen.GetInstanceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, InstanceID: id})
	if err != nil {
		return domain.InstanceRecord{}, missing(err)
	}
	return r.instance(row)
}

func (w writer) DeleteInstance(scope domain.Scope, id string) error {
	return w.q.DeleteInstance(w.ctx, sqlcgen.DeleteInstanceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, InstanceID: id})
}

func (r reader) Activity(key domain.ActivityKey) (domain.ActivityRecord, error) {
	row, err := r.q.GetActivity(r.ctx, sqlcgen.GetActivityParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ActivityID: key.ID})
	if err != nil {
		return domain.ActivityRecord{}, missing(err)
	}
	return r.activity(row)
}

func (r reader) Policy(key domain.PolicyKey) (domain.PolicyRecord, error) {
	row, err := r.q.GetPolicy(r.ctx, sqlcgen.GetPolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
	if err != nil {
		return domain.PolicyRecord{}, missing(err)
	}
	return r.policy(row)
}

func (w writer) DeletePolicy(key domain.PolicyKey) error {
	return w.q.DeletePolicy(w.ctx, sqlcgen.DeletePolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
}

func (r reader) Schedule(key domain.ScheduleKey) (domain.ScheduleRecord, error) {
	row, err := r.q.GetSchedule(r.ctx, sqlcgen.GetScheduleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
	if err != nil {
		return domain.ScheduleRecord{}, missing(err)
	}
	return r.schedule(row)
}

func (w writer) DeleteSchedule(key domain.ScheduleKey) error {
	return w.q.DeleteSchedule(w.ctx, sqlcgen.DeleteScheduleParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
}

func (r reader) Hook(key domain.HookKey) (domain.HookRecord, error) {
	row, err := r.q.GetHook(r.ctx, sqlcgen.GetHookParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
	if err != nil {
		return domain.HookRecord{}, missing(err)
	}
	return r.hook(row)
}

func (w writer) DeleteHook(key domain.HookKey) error {
	return w.q.DeleteHook(w.ctx, sqlcgen.DeleteHookParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.GroupKey.Name, Name: key.Name})
}

func (w writer) DeleteLifecycleAction(key domain.GroupKey, token string) error {
	return w.q.DeleteLifecycleAction(w.ctx, sqlcgen.DeleteLifecycleActionParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name, Token: token})
}

func (r reader) Groups(q domain.GroupQuery) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, HasNames: flag(len(q.Names) != 0), Names: namesJSON(q.Names), RowLimit: rowLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.group(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) Instances(key domain.GroupKey) ([]domain.InstanceRecord, error) {
	rows, err := r.q.ListInstances(r.ctx, sqlcgen.ListInstancesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.InstanceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.instance(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) Activities(scope domain.Scope, group string, includeDeleted bool) ([]domain.ActivityRecord, error) {
	rows, err := r.q.ListActivities(r.ctx, sqlcgen.ListActivitiesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, GroupName: group, IncludeDeleted: flag(includeDeleted)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ActivityRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.activity(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) Policies(key domain.GroupKey) ([]domain.PolicyRecord, error) {
	rows, err := r.q.ListPolicies(r.ctx, sqlcgen.ListPoliciesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PolicyRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.policy(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) Schedules(key domain.GroupKey) ([]domain.ScheduleRecord, error) {
	rows, err := r.q.ListSchedules(r.ctx, sqlcgen.ListSchedulesParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ScheduleRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.schedule(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) Hooks(key domain.GroupKey) ([]domain.HookRecord, error) {
	rows, err := r.q.ListHooks(r.ctx, sqlcgen.ListHooksParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.HookRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.hook(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) LifecycleActions(key domain.GroupKey) ([]domain.LifecycleAction, error) {
	rows, err := r.q.ListLifecycleActions(r.ctx, sqlcgen.ListLifecycleActionsParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, GroupName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LifecycleAction, 0, len(rows))
	for _, row := range rows {
		v, err := r.lifecycleAction(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) PendingSchedules() ([]domain.ScheduleRecord, error) {
	rows, err := r.q.PendingSchedules(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ScheduleRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.schedule(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) PendingLifecycleActions() ([]domain.LifecycleAction, error) {
	rows, err := r.q.PendingLifecycleActions(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.LifecycleAction, 0, len(rows))
	for _, row := range rows {
		v, err := r.lifecycleAction(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) GroupKeys(partition, accountID string) ([]domain.GroupKey, error) {
	rows, err := r.q.ListGroupKeys(r.ctx, sqlcgen.ListGroupKeysParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, groupKey(row.Partition, row.AccountID, row.Region, row.Name))
	}
	return out, nil
}

func (r reader) PendingGroups() ([]domain.GroupWork, error) {
	rows, err := r.q.PendingGroups(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupWork, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.GroupWork{Key: groupKey(row.Partition, row.AccountID, row.Region, row.Name), ID: row.NativeID, Version: uint64(row.Version), Due: row.ReconcileAt.Time, MetricAt: row.MetricAt.Time, Deleting: row.Deleting})
	}
	return out, nil
}

func (w writer) DeleteActivitiesBefore(scope domain.Scope, before time.Time) error {
	return w.q.DeleteActivitiesBefore(w.ctx, sqlcgen.DeleteActivitiesBeforeParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, BeforeTime: deadline(before)})
}
