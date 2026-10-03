package configservice

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type namedKey struct {
	Scope
	Name string
}
type evaluationKey struct {
	Scope
	RuleName, ResourceType, ResourceID string
}
type authorizationKey struct {
	Scope
	AccountID, Region string
}
type memoryState struct {
	sequence       int64
	recorders      map[Scope]Recorder
	channels       map[Scope]Channel
	items          map[int64]Item
	deliveries     map[namedKey]Delivery
	rules          map[namedKey]Rule
	evaluations    map[evaluationKey]Evaluation
	runs           map[namedKey]EvaluationRun
	aggregators    map[namedKey]Aggregator
	authorizations map[authorizationKey]AggregationAuthorization
	tags           map[namedKey]map[string]string
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(d, memoryState{
		recorders: map[Scope]Recorder{}, channels: map[Scope]Channel{}, items: map[int64]Item{},
		deliveries: map[namedKey]Delivery{}, rules: map[namedKey]Rule{}, evaluations: map[evaluationKey]Evaluation{},
		runs: map[namedKey]EvaluationRun{}, aggregators: map[namedKey]Aggregator{}, authorizations: map[authorizationKey]AggregationAuthorization{},
		tags: map[namedKey]map[string]string{},
	}, func(s memoryState) memoryState {
		// Nested values are immutable inside the store: writes and reads clone them.
		s.recorders = maps.Clone(s.recorders)
		s.channels = maps.Clone(s.channels)
		s.items = maps.Clone(s.items)
		s.deliveries = maps.Clone(s.deliveries)
		s.rules = maps.Clone(s.rules)
		s.evaluations = maps.Clone(s.evaluations)
		s.runs = maps.Clone(s.runs)
		s.aggregators = maps.Clone(s.aggregators)
		s.authorizations = maps.Clone(s.authorizations)
		s.tags = maps.Clone(s.tags)
		return s
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, t *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func (r memoryReader) Tags(s Scope, arn string) (map[string]string, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	return maps.Clone(r.s.tags[namedKey{s, arn}]), nil
}
func (w memoryWriter) PutTags(s Scope, arn string, tags map[string]string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := namedKey{s, arn}
	if len(tags) == 0 {
		delete(w.s.tags, key)
	} else {
		w.s.tags[key] = maps.Clone(tags)
	}
	return nil
}
func cloneRecorder(v Recorder) Recorder {
	v.ResourceTypes = slices.Clone(v.ResourceTypes)
	v.ExcludedTypes = slices.Clone(v.ExcludedTypes)
	return v
}
func cloneItem(v Item) Item {
	v.Tags = maps.Clone(v.Tags)
	v.Supplementary = maps.Clone(v.Supplementary)
	v.Relationships = slices.Clone(v.Relationships)
	return v
}
func cloneRule(v Rule) Rule {
	v.ResourceTypes = slices.Clone(v.ResourceTypes)
	v.SourceMessages = slices.Clone(v.SourceMessages)
	return v
}
func cloneAggregator(v Aggregator) Aggregator { v.Sources = slices.Clone(v.Sources); return v }
func compareScope(a, b Scope) int {
	if n := cmp.Compare(a.Partition, b.Partition); n != 0 {
		return n
	}
	if n := cmp.Compare(a.AccountID, b.AccountID); n != 0 {
		return n
	}
	return cmp.Compare(a.Region, b.Region)
}
func (r memoryReader) Recorder(s Scope) (Recorder, bool, error) {
	if err := r.t.Check(false); err != nil {
		return Recorder{}, false, err
	}
	v, ok := r.s.recorders[s]
	return cloneRecorder(v), ok, nil
}
func (r memoryReader) Channel(s Scope) (Channel, bool, error) {
	if err := r.t.Check(false); err != nil {
		return Channel{}, false, err
	}
	v, ok := r.s.channels[s]
	return v, ok, nil
}
func (r memoryReader) Items(s Scope) ([]Item, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Item{}
	for _, v := range r.s.items {
		if v.Scope == s {
			out = append(out, cloneItem(v))
		}
	}
	slices.SortFunc(out, func(a, b Item) int { return cmp.Compare(a.Sequence, b.Sequence) })
	return out, nil
}
func (r memoryReader) Deliveries() ([]Delivery, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(r.s.deliveries))
	for _, v := range r.s.deliveries {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Delivery) int {
		if n := a.Due.Compare(b.Due); n != 0 {
			return n
		}
		if n := compareScope(a.Scope, b.Scope); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (r memoryReader) Rules(s Scope) ([]Rule, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Rule{}
	for _, v := range r.s.rules {
		if v.Scope == s {
			out = append(out, cloneRule(v))
		}
	}
	slices.SortFunc(out, func(a, b Rule) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) Evaluations(s Scope) ([]Evaluation, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Evaluation{}
	for _, v := range r.s.evaluations {
		if v.Scope == s {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Evaluation) int {
		if n := cmp.Compare(a.RuleName, b.RuleName); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ResourceType, b.ResourceType); n != 0 {
			return n
		}
		return cmp.Compare(a.ResourceID, b.ResourceID)
	})
	return out, nil
}
func (r memoryReader) EvaluationRuns() ([]EvaluationRun, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := make([]EvaluationRun, 0, len(r.s.runs))
	for _, v := range r.s.runs {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b EvaluationRun) int {
		if n := a.Due.Compare(b.Due); n != 0 {
			return n
		}
		if n := compareScope(a.Scope, b.Scope); n != 0 {
			return n
		}
		return cmp.Compare(a.Token, b.Token)
	})
	return out, nil
}
func (r memoryReader) Aggregators(s Scope) ([]Aggregator, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []Aggregator{}
	for _, v := range r.s.aggregators {
		if v.Scope == s {
			out = append(out, cloneAggregator(v))
		}
	}
	slices.SortFunc(out, func(a, b Aggregator) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) AggregationAuthorizations(s Scope) ([]AggregationAuthorization, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []AggregationAuthorization{}
	for _, v := range r.s.authorizations {
		if v.Scope == s {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b AggregationAuthorization) int {
		if n := cmp.Compare(a.AccountID, b.AccountID); n != 0 {
			return n
		}
		return cmp.Compare(a.Region, b.Region)
	})
	return out, nil
}
func (w memoryWriter) PutRecorder(v Recorder) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.recorders[v.Scope] = cloneRecorder(v)
	return nil
}
func (w memoryWriter) DeleteRecorder(s Scope) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.recorders, s)
	return nil
}
func (w memoryWriter) PutChannel(v Channel) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.channels[v.Scope] = v
	return nil
}
func (w memoryWriter) DeleteChannel(s Scope) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.channels, s)
	return nil
}
func (w memoryWriter) AppendItem(v Item) (Item, error) {
	if err := w.t.Check(true); err != nil {
		return Item{}, err
	}
	w.s.sequence++
	v.Sequence = w.s.sequence
	w.s.items[v.Sequence] = cloneItem(v)
	return cloneItem(v), nil
}
func (w memoryWriter) PutDelivery(v Delivery) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.deliveries[namedKey{v.Scope, v.ID}] = v
	return nil
}
func (w memoryWriter) PutRule(v Rule) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.rules[namedKey{v.Scope, v.Name}] = cloneRule(v)
	return nil
}
func (w memoryWriter) DeleteRule(s Scope, name string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.rules, namedKey{s, name})
	for k, v := range w.s.evaluations {
		if v.Scope == s && v.RuleName == name {
			delete(w.s.evaluations, k)
		}
	}
	for k, v := range w.s.runs {
		if v.Scope == s && v.RuleName == name {
			delete(w.s.runs, k)
		}
	}
	return nil
}
func (w memoryWriter) PutEvaluation(v Evaluation) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.evaluations[evaluationKey{v.Scope, v.RuleName, v.ResourceType, v.ResourceID}] = v
	return nil
}
func (w memoryWriter) DeleteEvaluations(s Scope, name string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	for k, v := range w.s.evaluations {
		if v.Scope == s && v.RuleName == name {
			delete(w.s.evaluations, k)
		}
	}
	return nil
}
func (w memoryWriter) PutEvaluationRun(v EvaluationRun) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.runs[namedKey{v.Scope, v.Token}] = v
	return nil
}
func (w memoryWriter) PutAggregator(v Aggregator) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.aggregators[namedKey{v.Scope, v.Name}] = cloneAggregator(v)
	return nil
}
func (w memoryWriter) DeleteAggregator(s Scope, name string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.aggregators, namedKey{s, name})
	return nil
}
func (w memoryWriter) PutAggregationAuthorization(v AggregationAuthorization) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.authorizations[authorizationKey{v.Scope, v.AccountID, v.Region}] = v
	return nil
}
func (w memoryWriter) DeleteAggregationAuthorization(s Scope, account, region string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.authorizations, authorizationKey{s, account, region})
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
