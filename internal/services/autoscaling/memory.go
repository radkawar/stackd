package autoscaling

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/storage/memory"
)

type instanceKey struct {
	Scope
	ID string
}
type actionKey struct {
	GroupKey
	Token string
}
type memoryState struct {
	groups     map[GroupKey]GroupRecord
	instances  map[instanceKey]InstanceRecord
	activities map[ActivityKey]ActivityRecord
	policies   map[PolicyKey]PolicyRecord
	schedules  map[ScheduleKey]ScheduleRecord
	hooks      map[HookKey]HookRecord
	actions    map[actionKey]LifecycleAction
	refreshes  map[ActivityKey]RefreshRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{groups: map[GroupKey]GroupRecord{}, instances: map[instanceKey]InstanceRecord{}, activities: map[ActivityKey]ActivityRecord{}, policies: map[PolicyKey]PolicyRecord{}, schedules: map[ScheduleKey]ScheduleRecord{}, hooks: map[HookKey]HookRecord{}, actions: map[actionKey]LifecycleAction{}, refreshes: map[ActivityKey]RefreshRecord{}}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		return memoryState{groups: maps.Clone(s.groups), instances: maps.Clone(s.instances), activities: maps.Clone(s.activities), policies: maps.Clone(s.policies), schedules: maps.Clone(s.schedules), hooks: maps.Clone(s.hooks), actions: maps.Clone(s.actions), refreshes: maps.Clone(s.refreshes)}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneGroup(v GroupRecord) GroupRecord {
	v.Data = api.CloneAutoScalingGroup(v.Data)
	if v.PendingInstanceWarmup != nil {
		v.PendingInstanceWarmup = new(*v.PendingInstanceWarmup)
	}
	return v
}
func cloneInstance(v InstanceRecord) InstanceRecord { v.Data = api.CloneInstance(v.Data); return v }
func cloneActivity(v ActivityRecord) ActivityRecord {
	v.Data = api.CloneActivity(v.Data)
	v.LaunchTemplate = api.CloneLaunchTemplateSpecification(v.LaunchTemplate)
	v.LaunchTags = api.CloneTagDescriptionList(v.LaunchTags)
	if v.InstanceWarmup != nil {
		v.InstanceWarmup = new(*v.InstanceWarmup)
	}
	return v
}
func clonePolicy(v PolicyRecord) PolicyRecord { v.Data = api.CloneScalingPolicy(v.Data); return v }
func cloneSchedule(v ScheduleRecord) ScheduleRecord {
	v.Data = api.CloneScheduledUpdateGroupAction(v.Data)
	return v
}
func cloneHook(v HookRecord) HookRecord { v.Data = api.CloneLifecycleHook(v.Data); return v }
func compareGroups(a, b GroupKey) int {
	return cmp.Or(strings.Compare(a.Partition, b.Partition), strings.Compare(a.AccountID, b.AccountID), strings.Compare(a.Region, b.Region), strings.Compare(a.Name, b.Name))
}
func (r memoryReader) Group(key GroupKey) (GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return GroupRecord{}, err
	}
	v, ok := r.state.groups[key]
	if !ok {
		return GroupRecord{}, ErrNotFound
	}
	return cloneGroup(v), nil
}
func (r memoryReader) Groups(q GroupQuery) ([]GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []GroupRecord{}
	for key, v := range r.state.groups {
		if key.Scope == q.Scope && key.Name > q.After && (len(q.Names) == 0 || slices.Contains(q.Names, key.Name)) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b GroupRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneGroup(out[i])
	}
	return out, nil
}
func (r memoryReader) PendingGroups() ([]GroupWork, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []GroupWork
	for key, v := range r.state.groups {
		if !v.ReconcileAt.IsZero() || !v.MetricAt.IsZero() {
			out = append(out, GroupWork{Key: key, ID: v.ID, Version: v.Version, Due: v.ReconcileAt, MetricAt: v.MetricAt, Deleting: v.Deleting})
		}
	}
	slices.SortFunc(out, func(a, b GroupWork) int { return cmp.Or(a.Due.Compare(b.Due), compareGroups(a.Key, b.Key)) })
	return out, nil
}
func (r memoryReader) GroupKeys(partition, accountID string) ([]GroupKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []GroupKey
	for key := range r.state.groups {
		if key.Partition == partition && key.AccountID == accountID {
			out = append(out, key)
		}
	}
	slices.SortFunc(out, compareGroups)
	return out, nil
}
func (r memoryReader) Instances(key GroupKey) ([]InstanceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []InstanceRecord{}
	for _, v := range r.state.instances {
		if v.Group == key {
			out = append(out, cloneInstance(v))
		}
	}
	slices.SortFunc(out, func(a, b InstanceRecord) int {
		return strings.Compare(value(a.Data.InstanceId), value(b.Data.InstanceId))
	})
	return out, nil
}
func (r memoryReader) Instance(scope Scope, id string) (InstanceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return InstanceRecord{}, err
	}
	v, ok := r.state.instances[instanceKey{scope, id}]
	if !ok {
		return InstanceRecord{}, ErrNotFound
	}
	return cloneInstance(v), nil
}
func (r memoryReader) Activity(key ActivityKey) (ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ActivityRecord{}, err
	}
	v, ok := r.state.activities[key]
	if !ok {
		return ActivityRecord{}, ErrNotFound
	}
	return cloneActivity(v), nil
}
func (r memoryReader) Activities(scope Scope, group string, includeDeleted bool) ([]ActivityRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ActivityRecord{}
	for key, v := range r.state.activities {
		if key.Scope != scope || group != "" && v.Group.Name != group {
			continue
		}
		if current, ok := r.state.groups[v.Group]; !includeDeleted && (!ok || current.ID != v.GroupID) {
			continue
		}
		out = append(out, cloneActivity(v))
	}
	slices.SortFunc(out, func(a, b ActivityRecord) int {
		return cmp.Or(time.Time(*b.Data.StartTime).Compare(time.Time(*a.Data.StartTime)), strings.Compare(a.Key.ID, b.Key.ID))
	})
	return out, nil
}
func (r memoryReader) Policy(key PolicyKey) (PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PolicyRecord{}, err
	}
	v, ok := r.state.policies[key]
	if !ok {
		return PolicyRecord{}, ErrNotFound
	}
	return clonePolicy(v), nil
}
func (r memoryReader) Policies(key GroupKey) ([]PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PolicyRecord{}
	for k, v := range r.state.policies {
		if k.GroupKey == key {
			out = append(out, clonePolicy(v))
		}
	}
	slices.SortFunc(out, func(a, b PolicyRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Schedule(key ScheduleKey) (ScheduleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ScheduleRecord{}, err
	}
	v, ok := r.state.schedules[key]
	if !ok {
		return ScheduleRecord{}, ErrNotFound
	}
	return cloneSchedule(v), nil
}
func (r memoryReader) Schedules(key GroupKey) ([]ScheduleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ScheduleRecord{}
	for k, v := range r.state.schedules {
		if k.GroupKey == key {
			out = append(out, cloneSchedule(v))
		}
	}
	slices.SortFunc(out, func(a, b ScheduleRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) PendingSchedules() ([]ScheduleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []ScheduleRecord
	for _, v := range r.state.schedules {
		if !v.NextDue.IsZero() {
			out = append(out, cloneSchedule(v))
		}
	}
	slices.SortFunc(out, func(a, b ScheduleRecord) int {
		return cmp.Or(a.NextDue.Compare(b.NextDue), compareGroups(a.Key.GroupKey, b.Key.GroupKey), strings.Compare(a.Key.Name, b.Key.Name))
	})
	return out, nil
}
func (r memoryReader) Hook(key HookKey) (HookRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return HookRecord{}, err
	}
	v, ok := r.state.hooks[key]
	if !ok {
		return HookRecord{}, ErrNotFound
	}
	return cloneHook(v), nil
}
func (r memoryReader) Hooks(key GroupKey) ([]HookRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []HookRecord{}
	for k, v := range r.state.hooks {
		if k.GroupKey == key {
			out = append(out, cloneHook(v))
		}
	}
	slices.SortFunc(out, func(a, b HookRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) LifecycleActions(key GroupKey) ([]LifecycleAction, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []LifecycleAction{}
	for k, v := range r.state.actions {
		if k.GroupKey == key {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b LifecycleAction) int { return strings.Compare(a.Token, b.Token) })
	return out, nil
}
func (w memoryWriter) PutGroup(v GroupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.groups[v.Key] = cloneGroup(v)
	return nil
}
func (w memoryWriter) DeleteGroup(key GroupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.groups, key)
	for k, v := range w.state.instances {
		if v.Group == key {
			delete(w.state.instances, k)
		}
	}
	for k := range w.state.policies {
		if k.GroupKey == key {
			delete(w.state.policies, k)
		}
	}
	for k := range w.state.schedules {
		if k.GroupKey == key {
			delete(w.state.schedules, k)
		}
	}
	for k := range w.state.hooks {
		if k.GroupKey == key {
			delete(w.state.hooks, k)
		}
	}
	for k := range w.state.actions {
		if k.GroupKey == key {
			delete(w.state.actions, k)
		}
	}
	return nil
}
func (w memoryWriter) PutInstance(v InstanceRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.instances[instanceKey{v.Group.Scope, value(v.Data.InstanceId)}] = cloneInstance(v)
	return nil
}
func (w memoryWriter) DeleteInstance(scope Scope, id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.instances, instanceKey{scope, id})
	return nil
}
func (w memoryWriter) PutActivity(v ActivityRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.activities[v.Key] = cloneActivity(v)
	return nil
}
func (w memoryWriter) DeleteActivitiesBefore(scope Scope, before time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, v := range w.state.activities {
		if key.Scope == scope && v.Data.EndTime != nil && time.Time(*v.Data.EndTime).Before(before) {
			delete(w.state.activities, key)
		}
	}
	return nil
}
func (w memoryWriter) PutPolicy(v PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.policies[v.Key] = clonePolicy(v)
	return nil
}
func (w memoryWriter) DeletePolicy(key PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.policies, key)
	return nil
}
func (w memoryWriter) PutSchedule(v ScheduleRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.schedules[v.Key] = cloneSchedule(v)
	return nil
}
func (w memoryWriter) DeleteSchedule(key ScheduleKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.schedules, key)
	return nil
}
func (w memoryWriter) PutHook(v HookRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.hooks[v.Key] = cloneHook(v)
	return nil
}
func (w memoryWriter) DeleteHook(key HookKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.hooks, key)
	return nil
}
func (w memoryWriter) PutLifecycleAction(v LifecycleAction) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.actions[actionKey{v.Group, v.Token}] = v
	return nil
}
func (w memoryWriter) DeleteLifecycleAction(key GroupKey, token string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.actions, actionKey{key, token})
	return nil
}

func (r memoryReader) PendingLifecycleActions() ([]LifecycleAction, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []LifecycleAction
	for _, action := range r.state.actions {
		if !action.Deadline.IsZero() {
			out = append(out, action)
		}
	}
	slices.SortFunc(out, func(a, b LifecycleAction) int {
		return cmp.Or(a.Deadline.Compare(b.Deadline), compareGroups(a.Group, b.Group), strings.Compare(a.Token, b.Token))
	})
	return out, nil
}

func cloneRefresh(v RefreshRecord) RefreshRecord {
	v.Data = api.CloneInstanceRefresh(v.Data)
	v.Original = api.CloneLaunchTemplateSpecification(v.Original)
	v.Target = api.CloneLaunchTemplateSpecification(v.Target)
	v.Members = slices.Clone(v.Members)
	return v
}

func (r memoryReader) Refreshes(key GroupKey) ([]RefreshRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []RefreshRecord{}
	for _, v := range r.state.refreshes {
		if v.Group == key {
			out = append(out, cloneRefresh(v))
		}
	}
	slices.SortFunc(out, func(a, b RefreshRecord) int {
		return cmp.Or(b.RequestedAt.Compare(a.RequestedAt), strings.Compare(value(b.Data.InstanceRefreshId), value(a.Data.InstanceRefreshId)))
	})
	return out, nil
}

func (w memoryWriter) PutRefresh(v RefreshRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.refreshes[ActivityKey{Scope: v.Group.Scope, ID: value(v.Data.InstanceRefreshId)}] = cloneRefresh(v)
	return nil
}
