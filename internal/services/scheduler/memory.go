package scheduler

import (
	"context"
	"maps"
	"slices"
	"strings"

	"stackd/storage/memory"
)

type memoryState struct {
	groups     map[GroupKey]GroupRecord
	schedules  map[ScheduleKey]ScheduleRecord
	deliveries map[string]DeliveryRecord
}

type MemoryRepository struct {
	store *memory.Store[memoryState]
}

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{
		map[GroupKey]GroupRecord{},
		map[ScheduleKey]ScheduleRecord{},
		map[string]DeliveryRecord{},
	}, func(s memoryState) memoryState {
		return memoryState{
			maps.Clone(s.groups),
			maps.Clone(s.schedules),
			maps.Clone(s.deliveries),
		}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error {
		return fn(memoryReader{
			s,
			tx,
		})
	})
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{
			s,
			tx,
		}})
	})
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}

type memoryWriter struct {
	memoryReader
}

func (r memoryReader) Context() context.Context {
	return r.tx.Context()
}

func cloneTarget(v TargetRecord) TargetRecord {
	if v.ECS != nil {
		e := *v.ECS
		e.Subnets = slices.Clone(e.Subnets)
		e.SecurityGroups = slices.Clone(e.SecurityGroups)
		e.Capacity = slices.Clone(e.Capacity)
		e.Constraints = slices.Clone(e.Constraints)
		e.Placement = slices.Clone(e.Placement)
		e.Tags = slices.Clone(e.Tags)
		v.ECS = &e
	}
	return v
}

func cloneSchedule(v ScheduleRecord) ScheduleRecord {
	v.Target = cloneTarget(v.Target)
	v.Ciphertext = slices.Clone(v.Ciphertext)
	v.DataKey = slices.Clone(v.DataKey)
	if v.Next != nil {
		t := *v.Next
		v.Next = &t
	}
	if v.Start != nil {
		t := *v.Start
		v.Start = &t
	}
	if v.End != nil {
		t := *v.End
		v.End = &t
	}
	return v
}

func cloneDelivery(v DeliveryRecord) DeliveryRecord {
	v.Target = cloneTarget(v.Target)
	v.Ciphertext = slices.Clone(v.Ciphertext)
	v.DataKey = slices.Clone(v.DataKey)
	return v
}

func (r memoryReader) Group(k GroupKey) (GroupRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return GroupRecord{}, e
	}
	v, ok := r.s.groups[k]
	if !ok {
		return v, ErrNotFound
	}
	v.Tags = maps.Clone(v.Tags)
	return v, nil
}

func (r memoryReader) Groups(k Scope) ([]GroupRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []GroupRecord{}
	for key, v := range r.s.groups {
		if key.Scope == k {
			v.Tags = maps.Clone(v.Tags)
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b GroupRecord) int {
		return strings.Compare(a.Key.Name, b.Key.Name)
	})
	return out, nil
}

func (r memoryReader) Schedule(k ScheduleKey) (ScheduleRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return ScheduleRecord{}, e
	}
	v, ok := r.s.schedules[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneSchedule(v), nil
}

func (r memoryReader) Schedules(k Scope) ([]ScheduleRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ScheduleRecord{}
	for key, v := range r.s.schedules {
		if key.Group.Scope == k {
			out = append(out, cloneSchedule(v))
		}
	}
	slices.SortFunc(out, func(a, b ScheduleRecord) int {
		if n := strings.Compare(a.Key.Group.Name, b.Key.Group.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Key.Name, b.Key.Name)
	})
	return out, nil
}

func (r memoryReader) NextSchedule() (ScheduleRecord, bool, error) {
	if e := r.tx.Check(false); e != nil {
		return ScheduleRecord{}, false, e
	}
	var out ScheduleRecord
	found := false
	for _, v := range r.s.schedules {
		if v.Next != nil && (!found || v.Next.Before(*out.Next) || v.Next.Equal(*out.Next) && v.Key.ARN() < out.Key.ARN()) {
			out = v
			found = true
		}
	}
	return cloneSchedule(out), found, nil
}

func (r memoryReader) Delivery(id string) (DeliveryRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return DeliveryRecord{}, e
	}
	v, ok := r.s.deliveries[id]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDelivery(v), nil
}

func (r memoryReader) NextDelivery() (DeliveryRecord, bool, error) {
	if e := r.tx.Check(false); e != nil {
		return DeliveryRecord{}, false, e
	}
	var out DeliveryRecord
	found := false
	for _, v := range r.s.deliveries {
		if !found || v.Due.Before(out.Due) || v.Due.Equal(out.Due) && v.ID < out.ID {
			out = v
			found = true
		}
	}
	return cloneDelivery(out), found, nil
}

func (w memoryWriter) PutGroup(v GroupRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	v.Tags = maps.Clone(v.Tags)
	w.s.groups[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteGroup(k GroupKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.groups, k)
	return nil
}

func (w memoryWriter) PutSchedule(v ScheduleRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.schedules[v.Key] = cloneSchedule(v)
	return nil
}

func (w memoryWriter) DeleteSchedule(k ScheduleKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.schedules, k)
	return nil
}

func (w memoryWriter) PutDelivery(v DeliveryRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.deliveries[v.ID] = cloneDelivery(v)
	return nil
}

func (w memoryWriter) DeleteDelivery(id string) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.deliveries, id)
	return nil
}

func (w memoryWriter) DeleteScheduleDeliveries(k ScheduleKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	for id, v := range w.s.deliveries {
		if v.Schedule == k {
			delete(w.s.deliveries, id)
		}
	}
	return nil
}

func (w memoryWriter) DeleteGroupDeliveries(k GroupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for id, v := range w.s.deliveries {
		if v.Schedule.Group == k {
			delete(w.s.deliveries, id)
		}
	}
	return nil
}
