package elbv2

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"stackd/storage/memory"
)

type recordKey struct {
	Scope
	ARN string
}
type targetKey struct {
	Scope
	ARN, ID string
	Port    int32
}
type memoryState struct {
	next          uint64
	loadBalancers map[recordKey]LoadBalancerRecord
	targetGroups  map[recordKey]TargetGroupRecord
	listeners     map[recordKey]ListenerRecord
	rules         map[recordKey]RuleRecord
	targets       map[targetKey]TargetRecord
	metricSamples map[MetricPublicationKey]map[metricSampleKey]MetricSample
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{loadBalancers: map[recordKey]LoadBalancerRecord{}, targetGroups: map[recordKey]TargetGroupRecord{}, listeners: map[recordKey]ListenerRecord{}, rules: map[recordKey]RuleRecord{}, targets: map[targetKey]TargetRecord{}, metricSamples: map[MetricPublicationKey]map[metricSampleKey]MetricSample{}}, func(s memoryState) memoryState {
		s.loadBalancers = maps.Clone(s.loadBalancers)
		s.targetGroups = maps.Clone(s.targetGroups)
		s.listeners = maps.Clone(s.listeners)
		s.rules = maps.Clone(s.rules)
		s.targets = maps.Clone(s.targets)
		s.metricSamples = maps.Clone(s.metricSamples)
		for key, samples := range s.metricSamples {
			s.metricSamples[key] = maps.Clone(samples)
		}
		return s
	})}
}
func (m *MemoryRepository) View(ctx context.Context, f func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(ctx context.Context, f func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, f func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func (w memoryWriter) NextID() (uint64, error) {
	if e := w.t.Check(true); e != nil {
		return 0, e
	}
	w.s.next++
	return w.s.next, nil
}
func cloneLoadBalancer(v LoadBalancerRecord) LoadBalancerRecord {
	v.Data = api.CloneLoadBalancer(v.Data)
	v.Tags = api.CloneTagList(v.Tags)
	v.AttachmentIDs = maps.Clone(v.AttachmentIDs)
	v.AttachmentGenerations = maps.Clone(v.AttachmentGenerations)
	return v
}
func (r memoryReader) LoadBalancer(sc Scope, arn string) (LoadBalancerRecord, error) {
	if e := r.t.Check(false); e != nil {
		return LoadBalancerRecord{}, e
	}
	v, ok := r.s.loadBalancers[recordKey{sc, arn}]
	if !ok {
		return LoadBalancerRecord{}, ErrNotFound
	}
	return cloneLoadBalancer(v), nil
}
func (r memoryReader) LoadBalancers(sc Scope) ([]LoadBalancerRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []LoadBalancerRecord{}
	for _, v := range r.s.loadBalancers {
		if sc == (Scope{}) || sc == v.Scope {
			out = append(out, cloneLoadBalancer(v))
		}
	}
	slices.SortFunc(out, func(a, b LoadBalancerRecord) int {
		return cmp.Compare(value(a.Data.LoadBalancerArn), value(b.Data.LoadBalancerArn))
	})
	return out, nil
}
func (w memoryWriter) PutLoadBalancer(v LoadBalancerRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	// The metric sampler owns its deadline independently of control/runtime writes.
	v.NextMetricAt = w.s.loadBalancers[recordKey{v.Scope, value(v.Data.LoadBalancerArn)}].NextMetricAt
	w.s.loadBalancers[recordKey{v.Scope, value(v.Data.LoadBalancerArn)}] = cloneLoadBalancer(v)
	return nil
}
func (w memoryWriter) DeleteLoadBalancer(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.loadBalancers, recordKey{sc, arn})
	return nil
}
func cloneTargetGroup(v TargetGroupRecord) TargetGroupRecord {
	v.Data = api.CloneTargetGroup(v.Data)
	v.Tags = api.CloneTagList(v.Tags)
	return v
}
func (r memoryReader) TargetGroup(sc Scope, arn string) (TargetGroupRecord, error) {
	if e := r.t.Check(false); e != nil {
		return TargetGroupRecord{}, e
	}
	v, ok := r.s.targetGroups[recordKey{sc, arn}]
	if !ok {
		return TargetGroupRecord{}, ErrNotFound
	}
	return cloneTargetGroup(v), nil
}
func (r memoryReader) TargetGroups(sc Scope) ([]TargetGroupRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []TargetGroupRecord{}
	for _, v := range r.s.targetGroups {
		if sc == (Scope{}) || sc == v.Scope {
			out = append(out, cloneTargetGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b TargetGroupRecord) int {
		return cmp.Compare(value(a.Data.TargetGroupArn), value(b.Data.TargetGroupArn))
	})
	return out, nil
}
func (w memoryWriter) PutTargetGroup(v TargetGroupRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.targetGroups[recordKey{v.Scope, value(v.Data.TargetGroupArn)}] = cloneTargetGroup(v)
	return nil
}
func (w memoryWriter) DeleteTargetGroup(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.targetGroups, recordKey{sc, arn})
	return nil
}
func cloneListener(v ListenerRecord) ListenerRecord {
	v.Data = api.CloneListener(v.Data)
	v.Tags = api.CloneTagList(v.Tags)
	return v
}
func (r memoryReader) Listener(sc Scope, arn string) (ListenerRecord, error) {
	if e := r.t.Check(false); e != nil {
		return ListenerRecord{}, e
	}
	v, ok := r.s.listeners[recordKey{sc, arn}]
	if !ok {
		return ListenerRecord{}, ErrNotFound
	}
	return cloneListener(v), nil
}
func (r memoryReader) Listeners(sc Scope) ([]ListenerRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []ListenerRecord{}
	for _, v := range r.s.listeners {
		if sc == (Scope{}) || sc == v.Scope {
			out = append(out, cloneListener(v))
		}
	}
	slices.SortFunc(out, func(a, b ListenerRecord) int {
		return cmp.Compare(value(a.Data.ListenerArn), value(b.Data.ListenerArn))
	})
	return out, nil
}
func (w memoryWriter) PutListener(v ListenerRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.listeners[recordKey{v.Scope, value(v.Data.ListenerArn)}] = cloneListener(v)
	return nil
}
func (w memoryWriter) DeleteListener(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.listeners, recordKey{sc, arn})
	return nil
}
func cloneRule(v RuleRecord) RuleRecord {
	v.Data = api.CloneRule(v.Data)
	v.Tags = api.CloneTagList(v.Tags)
	return v
}
func (r memoryReader) Rule(sc Scope, arn string) (RuleRecord, error) {
	if e := r.t.Check(false); e != nil {
		return RuleRecord{}, e
	}
	v, ok := r.s.rules[recordKey{sc, arn}]
	if !ok {
		return RuleRecord{}, ErrNotFound
	}
	return cloneRule(v), nil
}
func (r memoryReader) Rules(sc Scope) ([]RuleRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []RuleRecord{}
	for _, v := range r.s.rules {
		if sc == (Scope{}) || sc == v.Scope {
			out = append(out, cloneRule(v))
		}
	}
	slices.SortFunc(out, func(a, b RuleRecord) int { return cmp.Compare(value(a.Data.RuleArn), value(b.Data.RuleArn)) })
	return out, nil
}
func (w memoryWriter) PutRule(v RuleRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.rules[recordKey{v.Scope, value(v.Data.RuleArn)}] = cloneRule(v)
	return nil
}
func (w memoryWriter) DeleteRule(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.rules, recordKey{sc, arn})
	return nil
}
func cloneTarget(v TargetRecord) TargetRecord { v.Data = api.CloneTargetDescription(v.Data); return v }
func (r memoryReader) Target(sc Scope, arn, id string, port int32) (TargetRecord, error) {
	if e := r.t.Check(false); e != nil {
		return TargetRecord{}, e
	}
	v, ok := r.s.targets[targetKey{sc, arn, id, port}]
	if !ok {
		return TargetRecord{}, ErrNotFound
	}
	return cloneTarget(v), nil
}
func (r memoryReader) Targets(sc Scope, arn string) ([]TargetRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []TargetRecord{}
	for _, v := range r.s.targets {
		if (sc == (Scope{}) || sc == v.Scope) && (arn == "" || arn == v.TargetGroupARN) {
			out = append(out, cloneTarget(v))
		}
	}
	slices.SortFunc(out, func(a, b TargetRecord) int {
		if c := cmp.Compare(a.TargetGroupARN, b.TargetGroupARN); c != 0 {
			return c
		}
		if c := cmp.Compare(value(a.Data.Id), value(b.Data.Id)); c != 0 {
			return c
		}
		return cmp.Compare(intValue(a.Data.Port), intValue(b.Data.Port))
	})
	return out, nil
}
func (w memoryWriter) PutTarget(v TargetRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.targets[targetKey{v.Scope, v.TargetGroupARN, value(v.Data.Id), int32(intValue(v.Data.Port))}] = cloneTarget(v)
	return nil
}
func (w memoryWriter) DeleteTarget(sc Scope, arn, id string, port int32) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.targets, targetKey{sc, arn, id, port})
	return nil
}
