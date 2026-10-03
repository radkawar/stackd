package applicationautoscaling

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/storage/memory"
)

type memoryState struct {
	targets           map[TargetKey]TargetRecord
	arns              map[string]TargetKey
	policies          map[PolicyKey]PolicyRecord
	schedules         map[ScheduleKey]ScheduleRecord
	activities        map[ActivityKey]ActivityRecord
	pendingActivities map[ActivityKey]ActivityRecord
	activitySequence  int64
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{targets: map[TargetKey]TargetRecord{}, arns: map[string]TargetKey{}, policies: map[PolicyKey]PolicyRecord{}, schedules: map[ScheduleKey]ScheduleRecord{}, activities: map[ActivityKey]ActivityRecord{}, pendingActivities: map[ActivityKey]ActivityRecord{}}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		return memoryState{targets: maps.Clone(s.targets), arns: maps.Clone(s.arns), policies: maps.Clone(s.policies), schedules: maps.Clone(s.schedules), activities: maps.Clone(s.activities), pendingActivities: maps.Clone(s.pendingActivities), activitySequence: s.activitySequence}
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

func cloneTarget(v TargetRecord) TargetRecord {
	v.Data = api.CloneScalableTarget(v.Data)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func clonePolicy(v PolicyRecord) PolicyRecord { v.Data = api.CloneScalingPolicy(v.Data); return v }
func cloneSchedule(v ScheduleRecord) ScheduleRecord {
	v.Data = api.CloneScheduledAction(v.Data)
	return v
}

func compareTargetKeys(a, b TargetKey) int {
	return cmp.Or(strings.Compare(a.Partition, b.Partition), strings.Compare(a.AccountID, b.AccountID), strings.Compare(a.Region, b.Region), strings.Compare(a.Namespace, b.Namespace), strings.Compare(a.ResourceID, b.ResourceID), strings.Compare(a.Dimension, b.Dimension))
}

func comparePolicyKeys(a, b PolicyKey) int {
	return cmp.Or(compareTargetKeys(a.TargetKey, b.TargetKey), strings.Compare(a.Name, b.Name))
}
func compareScheduleKeys(a, b ScheduleKey) int {
	return cmp.Or(compareTargetKeys(a.TargetKey, b.TargetKey), strings.Compare(a.Name, b.Name))
}

func (r memoryReader) Target(key TargetKey) (TargetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TargetRecord{}, err
	}
	record, ok := r.state.targets[key]
	if !ok {
		return TargetRecord{}, ErrNotFound
	}
	return cloneTarget(record), nil
}

func (r memoryReader) TargetByARN(scope Scope, arn string) (TargetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TargetRecord{}, err
	}
	key, ok := r.state.arns[arn]
	if !ok || key.Scope != scope {
		return TargetRecord{}, ErrNotFound
	}
	return cloneTarget(r.state.targets[key]), nil
}

func (r memoryReader) Targets(query TargetQuery) ([]TargetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TargetRecord{}
	for key, record := range r.state.targets {
		if key.Scope != query.Scope || key.Namespace != query.Namespace || (query.Dimension != "" && key.Dimension != query.Dimension) || (len(query.ResourceIDs) != 0 && !slices.Contains(query.ResourceIDs, key.ResourceID)) {
			continue
		}
		if compareListCursor(key, "", query.From) < 0 {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b TargetRecord) int { return compareTargetKeys(a.Key, b.Key) })
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit:query.Limit]
	}
	for i := range out {
		out[i] = cloneTarget(out[i])
	}
	return out, nil
}

func (r memoryReader) TargetKeys(partition, accountID string) ([]TargetKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []TargetKey
	for key := range r.state.targets {
		if key.Partition == partition && key.AccountID == accountID {
			out = append(out, key)
		}
	}
	slices.SortFunc(out, compareTargetKeys)
	return out, nil
}

func (r memoryReader) Policy(key PolicyKey) (PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PolicyRecord{}, err
	}
	record, ok := r.state.policies[key]
	if !ok {
		return PolicyRecord{}, ErrNotFound
	}
	return clonePolicy(record), nil
}

func (r memoryReader) Policies(query PolicyQuery) ([]PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var positions map[string]int
	if len(query.Names) != 0 {
		positions = make(map[string]int, len(query.Names))
		for i, name := range query.Names {
			if _, exists := positions[name]; !exists {
				positions[name] = i
			}
		}
	}
	out := []PolicyRecord{}
	for key, record := range r.state.policies {
		if key.Scope != query.Scope || key.Namespace != query.Namespace || (query.ResourceID != "" && key.ResourceID != query.ResourceID) || (query.Dimension != "" && key.Dimension != query.Dimension) {
			continue
		}
		if _, selected := positions[key.Name]; len(positions) != 0 && !selected {
			continue
		}
		order := compareListCursor(key.TargetKey, key.Name, query.From)
		if query.From != nil && len(positions) != 0 && positions[key.Name] != positions[query.From.Name] {
			order = cmp.Compare(positions[key.Name], positions[query.From.Name])
		}
		if order < 0 {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b PolicyRecord) int {
		return cmp.Or(cmp.Compare(positions[a.Key.Name], positions[b.Key.Name]), comparePolicyKeys(a.Key, b.Key))
	})
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit:query.Limit]
	}
	for i := range out {
		out[i] = clonePolicy(out[i])
	}
	return out, nil
}

func (r memoryReader) Schedule(key ScheduleKey) (ScheduleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ScheduleRecord{}, err
	}
	record, ok := r.state.schedules[key]
	if !ok {
		return ScheduleRecord{}, ErrNotFound
	}
	return cloneSchedule(record), nil
}

func (r memoryReader) Schedules(query ScheduleQuery) ([]ScheduleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ScheduleRecord{}
	for key, record := range r.state.schedules {
		if key.Scope != query.Scope || key.Namespace != query.Namespace || (query.ResourceID != "" && key.ResourceID != query.ResourceID) || (query.Dimension != "" && key.Dimension != query.Dimension) || (len(query.Names) != 0 && !slices.Contains(query.Names, key.Name)) {
			continue
		}
		if compareListCursor(key.TargetKey, key.Name, query.From) < 0 {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b ScheduleRecord) int { return compareScheduleKeys(a.Key, b.Key) })
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[:query.Limit:query.Limit]
	}
	for i := range out {
		out[i] = cloneSchedule(out[i])
	}
	return out, nil
}

func (r memoryReader) NextTargetReconcile() (TargetKey, time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return TargetKey{}, time.Time{}, false, err
	}
	var key TargetKey
	var due time.Time
	for candidate, record := range r.state.targets {
		if !record.ReconcileAt.IsZero() && (due.IsZero() || record.ReconcileAt.Before(due) || (record.ReconcileAt.Equal(due) && compareTargetKeys(candidate, key) < 0)) {
			key, due = candidate, record.ReconcileAt
		}
	}
	return key, due, !due.IsZero(), nil
}

func (r memoryReader) NextSchedule() (ScheduleKey, time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ScheduleKey{}, time.Time{}, false, err
	}
	var key ScheduleKey
	var due time.Time
	for candidate, record := range r.state.schedules {
		if !record.NextDue.IsZero() && (due.IsZero() || record.NextDue.Before(due) || (record.NextDue.Equal(due) && compareScheduleKeys(candidate, key) < 0)) {
			key, due = candidate, record.NextDue
		}
	}
	return key, due, !due.IsZero(), nil
}

func (w memoryWriter) PutTarget(record TargetRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if previous, ok := w.state.targets[record.Key]; ok {
		delete(w.state.arns, value(previous.Data.ScalableTargetARN))
	}
	w.state.targets[record.Key] = cloneTarget(record)
	w.state.arns[value(record.Data.ScalableTargetARN)] = record.Key
	return nil
}

func (w memoryWriter) DeleteTarget(key TargetKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if previous, ok := w.state.targets[key]; ok {
		delete(w.state.arns, value(previous.Data.ScalableTargetARN))
	}
	delete(w.state.targets, key)
	for child := range w.state.policies {
		if child.TargetKey == key {
			delete(w.state.policies, child)
		}
	}
	for child := range w.state.schedules {
		if child.TargetKey == key {
			delete(w.state.schedules, child)
		}
	}
	return nil
}

func (w memoryWriter) PutPolicy(record PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.policies[record.Key] = clonePolicy(record)
	return nil
}

func (w memoryWriter) DeletePolicy(key PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.policies, key)
	return nil
}

func (w memoryWriter) PutSchedule(record ScheduleRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.state.schedules[record.Key] = cloneSchedule(record)
	return nil
}

func (w memoryWriter) DeleteSchedule(key ScheduleKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.schedules, key)
	return nil
}
