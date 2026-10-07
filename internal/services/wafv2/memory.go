package wafv2

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/storage/memory"
)

type arnKey struct {
	Scope
	ARN string
}
type sampleKey struct {
	Scope
	WebACLARN, Metric string
}
type populationKey struct {
	sampleKey
	Minute time.Time
}
type memoryState struct {
	webACLs      map[arnKey]WebACL
	ipSets       map[arnKey]IPSet
	associations map[arnKey]Association
	metrics      map[MetricKey]map[string]int64
	samples      map[sampleKey][]SampledRequest
	population   map[populationKey]int64
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	initial := memoryState{map[arnKey]WebACL{}, map[arnKey]IPSet{}, map[arnKey]Association{}, map[MetricKey]map[string]int64{}, map[sampleKey][]SampledRequest{}, map[populationKey]int64{}}
	return &MemoryRepository{memory.New(d, initial, func(v memoryState) memoryState {
		v.webACLs = maps.Clone(v.webACLs)
		v.ipSets = maps.Clone(v.ipSets)
		v.associations = maps.Clone(v.associations)
		metrics := make(map[MetricKey]map[string]int64, len(v.metrics))
		for k, m := range v.metrics {
			metrics[k] = maps.Clone(m)
		}
		v.metrics = metrics
		v.samples = maps.Clone(v.samples)
		v.population = maps.Clone(v.population)
		return v
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

// Definitions are treated as immutable values once stored; mutating commands
// always construct a fresh Definition, so only maps and slices are cloned here.
func cloneWebACL(v WebACL) WebACL { v.Tags = maps.Clone(v.Tags); return v }
func cloneIPSet(v IPSet) IPSet {
	v.Tags = maps.Clone(v.Tags)
	v.Addresses = slices.Clone(v.Addresses)
	return v
}

func (r memoryReader) WebACL(sc Scope, arn string) (WebACL, error) {
	if e := r.t.Check(false); e != nil {
		return WebACL{}, e
	}
	v, ok := r.s.webACLs[arnKey{sc, arn}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneWebACL(v), nil
}
func (r memoryReader) WebACLs(sc Scope) ([]WebACL, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []WebACL{}
	for k, v := range r.s.webACLs {
		if k.Scope == sc {
			out = append(out, cloneWebACL(v))
		}
	}
	slices.SortFunc(out, func(a, b WebACL) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out, nil
}
func (r memoryReader) IPSet(sc Scope, arn string) (IPSet, error) {
	if e := r.t.Check(false); e != nil {
		return IPSet{}, e
	}
	v, ok := r.s.ipSets[arnKey{sc, arn}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneIPSet(v), nil
}
func (r memoryReader) IPSets(sc Scope) ([]IPSet, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []IPSet{}
	for k, v := range r.s.ipSets {
		if k.Scope == sc {
			out = append(out, cloneIPSet(v))
		}
	}
	slices.SortFunc(out, func(a, b IPSet) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out, nil
}
func (r memoryReader) Association(sc Scope, resource string) (Association, error) {
	if e := r.t.Check(false); e != nil {
		return Association{}, e
	}
	v, ok := r.s.associations[arnKey{sc, resource}]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Associations(sc Scope, webACL string) ([]Association, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Association{}
	for k, v := range r.s.associations {
		if k.Scope == sc && v.WebACLARN == webACL {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Association) int { return cmp.Compare(a.ResourceARN, b.ResourceARN) })
	return out, nil
}
func compareMetricKeys(a, b MetricKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute), cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.WebACL, b.WebACL), cmp.Compare(a.Rule, b.Rule))
}
func (r memoryReader) NextMetricPublication() (MetricKey, error) {
	if e := r.t.Check(false); e != nil {
		return MetricKey{}, e
	}
	var next MetricKey
	found := false
	for k := range r.s.metrics {
		if !found || compareMetricKeys(k, next) < 0 {
			next, found = k, true
		}
	}
	if !found {
		return next, ErrNotFound
	}
	return next, nil
}
func (r memoryReader) MetricSamples(key MetricKey) ([]MetricSample, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []MetricSample{}
	for name, count := range r.s.metrics[key] {
		out = append(out, MetricSample{name, count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) SampledRequests(sc Scope, webACL, metric string, from, to time.Time, limit int) ([]SampledRequest, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []SampledRequest{}
	for _, v := range r.s.samples[sampleKey{sc, webACL, metric}] {
		if !v.At.Before(from) && v.At.Before(to) && len(out) < limit {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r memoryReader) SamplePopulation(sc Scope, webACL, metric string, from, to time.Time) (int64, error) {
	if e := r.t.Check(false); e != nil {
		return 0, e
	}
	var total int64
	for k, n := range r.s.population {
		if k.sampleKey == (sampleKey{sc, webACL, metric}) && !k.Minute.Before(from.Truncate(time.Minute)) && k.Minute.Before(to) {
			total += n
		}
	}
	return total, nil
}
func (r memoryReader) SampleCount(sc Scope, webACL, metric string, from time.Time) (int64, error) {
	if e := r.t.Check(false); e != nil {
		return 0, e
	}
	var n int64
	for _, v := range r.s.samples[sampleKey{sc, webACL, metric}] {
		if !v.At.Before(from) {
			n++
		}
	}
	return n, nil
}

func (w memoryWriter) PutWebACL(v WebACL) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.webACLs[arnKey{v.Scope, v.ARN}] = cloneWebACL(v)
	return nil
}
func (w memoryWriter) DeleteWebACL(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.webACLs, arnKey{sc, arn})
	return nil
}
func (w memoryWriter) PutIPSet(v IPSet) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.ipSets[arnKey{v.Scope, v.ARN}] = cloneIPSet(v)
	return nil
}
func (w memoryWriter) DeleteIPSet(sc Scope, arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.ipSets, arnKey{sc, arn})
	return nil
}
func (w memoryWriter) PutAssociation(v Association) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.associations[arnKey{v.Scope, v.ResourceARN}] = v
	return nil
}
func (w memoryWriter) DeleteAssociation(sc Scope, resource string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.associations, arnKey{sc, resource})
	return nil
}
func (w memoryWriter) AddMetricSample(key MetricKey, sample MetricSample) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	counts := maps.Clone(w.s.metrics[key])
	if counts == nil {
		counts = map[string]int64{}
	}
	counts[sample.Name] += sample.Count
	w.s.metrics[key] = counts
	return nil
}
func (w memoryWriter) DeleteMetricPublication(key MetricKey) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.metrics, key)
	return nil
}
func (w memoryWriter) PutSampledRequest(v SampledRequest) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	k := sampleKey{v.Scope, v.WebACLARN, v.MetricName}
	w.s.samples[k] = append(slices.Clone(w.s.samples[k]), v)
	return nil
}
func (w memoryWriter) AddSamplePopulation(sc Scope, webACL, metric string, minute time.Time, n int64) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.population[populationKey{sampleKey{sc, webACL, metric}, minute}] += n
	return nil
}
func (w memoryWriter) PruneSamples(before time.Time) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	for k, rows := range w.s.samples {
		kept := slices.DeleteFunc(slices.Clone(rows), func(v SampledRequest) bool { return v.At.Before(before) })
		if len(kept) == 0 {
			delete(w.s.samples, k)
		} else {
			w.s.samples[k] = kept
		}
	}
	for k := range w.s.population {
		if k.Minute.Before(before.Truncate(time.Minute)) {
			delete(w.s.population, k)
		}
	}
	return nil
}
