package xray

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	"stackd/storage/memory"
)

type memoryState struct {
	segments                map[SegmentKey]SegmentRecord
	policies                map[PolicyKey]PolicyRecord
	samplingRules           map[SamplingRuleKey]SamplingRuleRecord
	samplingClients         map[SamplingClientKey]SamplingClientRecord
	samplingStatistics      map[SamplingStatisticKey]SamplingStatisticRecord
	samplingModified        map[Scope]time.Time
	samplingBoostStatistics map[SamplingBoostStatisticKey]SamplingBoostStatisticRecord
	samplingBoosts          map[SamplingRuleKey]SamplingBoostRecord
	traces                  map[TraceKey]TraceRecord
	groups                  map[GroupKey]GroupRecord
	groupTraces             map[groupTraceKey]GroupMembership
	groupMetrics            map[GroupMetricKey]int64
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		segments: map[SegmentKey]SegmentRecord{}, policies: map[PolicyKey]PolicyRecord{},
		samplingRules:           map[SamplingRuleKey]SamplingRuleRecord{},
		samplingClients:         map[SamplingClientKey]SamplingClientRecord{},
		samplingStatistics:      map[SamplingStatisticKey]SamplingStatisticRecord{},
		samplingModified:        map[Scope]time.Time{},
		samplingBoostStatistics: map[SamplingBoostStatisticKey]SamplingBoostStatisticRecord{},
		samplingBoosts:          map[SamplingRuleKey]SamplingBoostRecord{},
		traces:                  map[TraceKey]TraceRecord{},
		groups:                  map[GroupKey]GroupRecord{},
		groupTraces:             map[groupTraceKey]GroupMembership{},
		groupMetrics:            map[GroupMetricKey]int64{},
	}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.segments = maps.Clone(s.segments)
		s.policies = maps.Clone(s.policies)
		s.samplingRules = maps.Clone(s.samplingRules)
		s.samplingClients = maps.Clone(s.samplingClients)
		s.samplingStatistics = maps.Clone(s.samplingStatistics)
		s.samplingModified = maps.Clone(s.samplingModified)
		s.samplingBoostStatistics = maps.Clone(s.samplingBoostStatistics)
		s.samplingBoosts = maps.Clone(s.samplingBoosts)
		s.traces = maps.Clone(s.traces)
		s.groups = maps.Clone(s.groups)
		s.groupTraces = maps.Clone(s.groupTraces)
		s.groupMetrics = maps.Clone(s.groupMetrics)
		return s
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
	s  *memoryState
	tx *memory.Transaction
}

type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneSegment(v SegmentRecord) SegmentRecord {
	if v.End != nil {
		v.End = new(*v.End)
	}
	if v.Completed != nil {
		v.Completed = new(*v.Completed)
	}
	return v
}

func clonePolicy(v PolicyRecord) PolicyRecord {
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	return v
}

func (r memoryReader) Segment(key SegmentKey) (SegmentRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SegmentRecord{}, err
	}
	v, ok := r.s.segments[key]
	if !ok {
		return SegmentRecord{}, ErrNotFound
	}
	return cloneSegment(v), nil
}

func (r memoryReader) TraceSegments(key TraceKey) ([]SegmentRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SegmentRecord, 0)
	for k, v := range r.s.segments {
		if k.TraceKey == key {
			rows = append(rows, cloneSegment(v))
		}
	}
	slices.SortFunc(rows, func(a, b SegmentRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (r memoryReader) EarliestSegmentReceipt() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	var earliest time.Time
	found := false
	for _, row := range r.s.segments {
		if !found || row.Received.Before(earliest) {
			earliest, found = row.Received, true
		}
	}
	return earliest, found, nil
}

func (r memoryReader) ResourcePolicies(scope Scope) ([]PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]PolicyRecord, 0)
	for k, v := range r.s.policies {
		if k.Scope == scope {
			rows = append(rows, clonePolicy(v))
		}
	}
	slices.SortFunc(rows, func(a, b PolicyRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (w memoryWriter) PutSegment(v SegmentRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.segments[v.Key] = cloneSegment(v)
	return nil
}

func (w memoryWriter) DeleteExpiredSegments(cutoff time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	remaining := map[TraceKey]bool{}
	for key, row := range w.s.segments {
		if !row.Received.After(cutoff) {
			delete(w.s.segments, key)
			remaining[key.TraceKey] = false
		}
	}
	if len(remaining) == 0 {
		return nil
	}
	for key := range w.s.segments {
		if _, affected := remaining[key.TraceKey]; affected {
			remaining[key.TraceKey] = true
		}
	}
	for key, exists := range remaining {
		if !exists {
			delete(w.s.traces, key)
		}
	}
	for key := range w.s.groupTraces {
		if exists, affected := remaining[key.Trace]; affected && !exists {
			delete(w.s.groupTraces, key)
		}
	}
	return nil
}

func (w memoryWriter) PutResourcePolicy(v PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.policies[v.Key] = clonePolicy(v)
	return nil
}

func (w memoryWriter) DeleteResourcePolicy(key PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.policies, key)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
