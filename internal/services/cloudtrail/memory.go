package cloudtrail

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"

	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

type deliveryStatusKey struct {
	trailID     string
	destination DestinationKind
}

type memoryState struct {
	trails         map[TrailKey]TrailRecord
	statuses       map[deliveryStatusKey]DeliveryStatus
	deliveries     map[string]DeliveryRecord
	events         map[string][]string
	digestKeys     map[string]DigestKeyRecord
	digestStreams  map[string]DigestStream
	digestLogs     map[string]DigestLog
	digestStatuses map[string]DigestStatus
}

// MemoryRepository participates in the native shared transaction domain.
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	if d == nil {
		d = memory.NewDomain()
	}
	state := memoryState{trails: map[TrailKey]TrailRecord{}, statuses: map[deliveryStatusKey]DeliveryStatus{}, deliveries: map[string]DeliveryRecord{}, events: map[string][]string{}}
	state.digestKeys = map[string]DigestKeyRecord{}
	state.digestStreams = map[string]DigestStream{}
	state.digestLogs = map[string]DigestLog{}
	state.digestStatuses = map[string]DigestStatus{}
	return &MemoryRepository{store: memory.New(d, state, func(s memoryState) memoryState {
		return memoryState{trails: maps.Clone(s.trails), statuses: maps.Clone(s.statuses), deliveries: maps.Clone(s.deliveries), events: maps.Clone(s.events), digestKeys: maps.Clone(s.digestKeys), digestStreams: maps.Clone(s.digestStreams), digestLogs: maps.Clone(s.digestLogs), digestStatuses: maps.Clone(s.digestStatuses)}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	state *memoryState
	tx    *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func cloneTrail(v TrailRecord) TrailRecord {
	v.Started, v.Stopped = clonePointer(v.Started), clonePointer(v.Stopped)
	v.StopAfter = clonePointer(v.StopAfter)
	v.Tags = maps.Clone(v.Tags)
	v.Selection.Basic = slices.Clone(v.Selection.Basic)
	for i := range v.Selection.Basic {
		s := &v.Selection.Basic[i]
		s.ReadOnly = clonePointer(s.ReadOnly)
		s.ExcludedSources = slices.Clone(s.ExcludedSources)
		s.DataResources = slices.Clone(s.DataResources)
		for j := range s.DataResources {
			s.DataResources[j].ARNPrefixes = slices.Clone(s.DataResources[j].ARNPrefixes)
		}
	}
	v.Selection.Advanced = slices.Clone(v.Selection.Advanced)
	for i := range v.Selection.Advanced {
		s := &v.Selection.Advanced[i]
		s.Fields = slices.Clone(s.Fields)
		for j := range s.Fields {
			f := &s.Fields[j]
			f.Tests = slices.Clone(f.Tests)
			for k := range f.Tests {
				f.Tests[k].Values = slices.Clone(f.Tests[k].Values)
			}
		}
	}
	return v
}
func cloneStatus(v DeliveryStatus) DeliveryStatus {
	v.LastAttempt, v.LastSuccess = clonePointer(v.LastAttempt), clonePointer(v.LastSuccess)
	return v
}
func compareTrail(a, b TrailRecord) int {
	if n := cmp.Compare(a.Key.Partition, b.Key.Partition); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Key.AccountID, b.Key.AccountID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Key.Region, b.Key.Region); n != 0 {
		return n
	}
	return cmp.Compare(a.Key.Name, b.Key.Name)
}
func (r memoryReader) Trail(key TrailKey) (TrailRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TrailRecord{}, err
	}
	v, ok := r.state.trails[key]
	if !ok {
		return TrailRecord{}, ErrNotFound
	}
	return cloneTrail(v), nil
}
func (r memoryReader) Trails(partition, accountID string) ([]TrailRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TrailRecord{}
	for k, v := range r.state.trails {
		if k.Partition == partition && k.AccountID == accountID {
			out = append(out, cloneTrail(v))
		}
	}
	slices.SortFunc(out, compareTrail)
	return out, nil
}
func (r memoryReader) HasOrganizationTrails(partition string) (bool, error) {
	if err := r.tx.Check(false); err != nil {
		return false, err
	}
	for k, trail := range r.state.trails {
		if k.Partition == partition && trail.OrganizationID != "" {
			return true, nil
		}
	}
	return false, nil
}
func (r memoryReader) DeliveryStatus(id string, kind DestinationKind) (DeliveryStatus, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryStatus{}, err
	}
	v, ok := r.state.statuses[deliveryStatusKey{id, kind}]
	if !ok {
		return DeliveryStatus{}, ErrNotFound
	}
	return cloneStatus(v), nil
}
func (r memoryReader) Delivery(id string) (DeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryRecord{}, err
	}
	v, ok := r.state.deliveries[id]
	if !ok {
		return DeliveryRecord{}, ErrNotFound
	}
	return v, nil
}
func deliveryBefore(a, b DeliveryRecord) bool {
	return a.Due.Before(b.Due) || a.Due.Equal(b.Due) && a.ID < b.ID
}
func (r memoryReader) OpenDelivery(trailID, accountID, region string, kind DestinationKind) (DeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryRecord{}, err
	}
	var out DeliveryRecord
	found := false
	for _, v := range r.state.deliveries {
		if v.TrailID == trailID && v.AccountID == accountID && v.Region == region && v.Destination == kind && !v.Sealed && (!found || deliveryBefore(v, out)) {
			out, found = v, true
		}
	}
	if !found {
		return DeliveryRecord{}, ErrNotFound
	}
	return out, nil
}
func (r memoryReader) DeliveryEventIDs(id string) ([]string, error) {
	if _, err := r.Delivery(id); err != nil {
		return nil, err
	}
	return slices.Clone(r.state.events[id]), nil
}
func (r memoryReader) NextDelivery() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var out DeliveryRecord
	found := false
	for _, v := range r.state.deliveries {
		if !found || deliveryBefore(v, out) {
			out, found = v, true
		}
	}
	return scheduler.Job{Key: out.ID, Due: out.Due, Version: out.Version}, found, nil
}
func (w memoryWriter) PutTrail(v TrailRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.state.trails[v.Key]; ok && old.ID != v.ID {
		return errors.New("CloudTrail trail identity is immutable")
	}
	for k, old := range w.state.trails {
		if old.ID == v.ID && k != v.Key {
			return errors.New("CloudTrail trail identity already exists")
		}
	}
	if old, ok := w.state.trails[v.Key]; ok && (old.LogsGroupARN != v.LogsGroupARN || old.LogsRoleARN != v.LogsRoleARN) {
		// Retire only the changed edge. Deleting retained IDs also fences
		// completion of a write that was already outside the transaction.
		delete(w.state.statuses, deliveryStatusKey{v.ID, DestinationLogs})
		for id, d := range w.state.deliveries {
			if d.TrailID == v.ID && d.Destination == DestinationLogs {
				delete(w.state.deliveries, id)
				delete(w.state.events, id)
			}
		}
	}
	w.state.trails[v.Key] = cloneTrail(v)
	return nil
}
func (w memoryWriter) DeleteTrail(key TrailKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.state.trails[key]
	if !ok {
		return nil
	}
	delete(w.state.trails, key)
	for k, status := range w.state.digestStatuses {
		if status.TrailID == v.ID {
			delete(w.state.digestStatuses, k)
		}
	}
	for k := range w.state.statuses {
		if k.trailID == v.ID {
			delete(w.state.statuses, k)
		}
	}
	for id, d := range w.state.deliveries {
		if d.TrailID == v.ID {
			delete(w.state.deliveries, id)
			delete(w.state.events, id)
		}
	}
	return nil
}
func (r memoryReader) hasTrail(id string) bool {
	for _, v := range r.state.trails {
		if v.ID == id {
			return true
		}
	}
	return false
}
func (w memoryWriter) PutDeliveryStatus(v DeliveryStatus) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if !w.hasTrail(v.TrailID) {
		return ErrNotFound
	}
	if v.Destination != DestinationS3 && v.Destination != DestinationLogs && v.Destination != DestinationSNS {
		return errors.New("unknown CloudTrail delivery destination")
	}
	w.state.statuses[deliveryStatusKey{v.TrailID, v.Destination}] = cloneStatus(v)
	return nil
}
func (w memoryWriter) PutDelivery(v DeliveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	trail, ok := w.state.trails[v.Trail]
	if !ok || trail.ID != v.TrailID {
		return ErrNotFound
	}
	if v.Destination != DestinationS3 && v.Destination != DestinationLogs && v.Destination != DestinationSNS {
		return errors.New("unknown CloudTrail delivery destination")
	}
	if old, ok := w.state.deliveries[v.ID]; ok && old.TrailID != v.TrailID {
		return errors.New("CloudTrail delivery identity is immutable")
	}
	w.state.deliveries[v.ID] = v
	return nil
}
func (w memoryWriter) AppendDeliveryEvent(id, eventID string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.state.deliveries[id]; !ok {
		return ErrNotFound
	}
	// Snapshots retain their own slice lengths; existing entries never change.
	// Appending beyond that length cannot alter an earlier snapshot's records.
	w.state.events[id] = append(w.state.events[id], eventID)
	return nil
}
func (w memoryWriter) DeleteDelivery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.state.deliveries, id)
	delete(w.state.events, id)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
