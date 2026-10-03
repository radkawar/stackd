package guardduty

import (
	"cmp"
	"context"
	"maps"
	"slices"

	api "stackd/internal/awsapi/guardduty"
	"stackd/journal"
	"stackd/storage/memory"
)

type detectorKey struct {
	Scope
	ID string
}
type childKey struct {
	detectorKey
	Name string
}
type memoryState struct {
	detectors    map[detectorKey]Detector
	findings     map[childKey]Finding
	filters      map[childKey]Filter
	ipLists      map[ipListKey]IPList
	ipRanges     map[ipListKey][]IPRange
	destinations map[childKey]PublishingDestination
	exports      map[findingExportKey]FindingExport
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	state := memoryState{detectors: map[detectorKey]Detector{}, findings: map[childKey]Finding{}, filters: map[childKey]Filter{}, ipLists: map[ipListKey]IPList{}, ipRanges: map[ipListKey][]IPRange{}}
	state.destinations = map[childKey]PublishingDestination{}
	state.exports = map[findingExportKey]FindingExport{}
	return &MemoryRepository{memory.New(domain, state, func(s memoryState) memoryState {
		s.detectors = maps.Clone(s.detectors)
		s.findings = maps.Clone(s.findings)
		s.filters = maps.Clone(s.filters)
		s.ipLists = maps.Clone(s.ipLists)
		// Range snapshots are immutable; only ingestion replaces a list's slice.
		s.ipRanges = maps.Clone(s.ipRanges)
		s.destinations = maps.Clone(s.destinations)
		s.exports = maps.Clone(s.exports)
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
func cloneDetector(v Detector) Detector {
	v.Tags = maps.Clone(v.Tags)
	v.Features = slices.Clone(v.Features)
	for i := range v.Features {
		v.Features[i].Additional = slices.Clone(v.Features[i].Additional)
	}
	return v
}
func cloneFinding(v Finding) Finding {
	v.Observation.ThreatListNames = slices.Clone(v.Observation.ThreatListNames)
	if v.Observation.Kubernetes != nil {
		audit := journal.CloneKubernetesAudit(*v.Observation.Kubernetes)
		v.Observation.Kubernetes = &audit
	}
	return v
}
func cloneFilter(v Filter) Filter {
	v.Tags = maps.Clone(v.Tags)
	v.Criteria = api.CloneFindingCriteria(v.Criteria)
	return v
}
func (r memoryReader) Detector(sc Scope, id string) (Detector, error) {
	if err := r.t.Check(false); err != nil {
		return Detector{}, err
	}
	v, ok := r.s.detectors[detectorKey{sc, id}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDetector(v), nil
}
func (r memoryReader) AllDetectors() ([]Detector, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := make([]Detector, 0, len(r.s.detectors))
	for _, v := range r.s.detectors {
		out = append(out, cloneDetector(v))
	}
	slices.SortFunc(out, func(a, b Detector) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutDetector(v Detector) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.detectors[detectorKey{v.Scope, v.ID}] = cloneDetector(v)
	return nil
}
func (w memoryWriter) DeleteDetector(sc Scope, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := detectorKey{sc, id}
	delete(w.s.detectors, key)
	for k := range w.s.findings {
		if k.detectorKey == key {
			delete(w.s.findings, k)
		}
	}
	for k := range w.s.filters {
		if k.detectorKey == key {
			delete(w.s.filters, k)
		}
	}
	for k := range w.s.ipLists {
		if k.detectorKey == key {
			delete(w.s.ipLists, k)
			delete(w.s.ipRanges, k)
		}
	}
	for k := range w.s.destinations {
		if k.detectorKey == key {
			delete(w.s.destinations, k)
		}
	}
	for k := range w.s.exports {
		if k.detectorKey == key {
			delete(w.s.exports, k)
		}
	}
	return nil
}
func (r memoryReader) Finding(sc Scope, detector, id string) (Finding, error) {
	if err := r.t.Check(false); err != nil {
		return Finding{}, err
	}
	v, ok := r.s.findings[childKey{detectorKey{sc, detector}, id}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneFinding(v), nil
}
func (r memoryReader) Findings(sc Scope, detector string) ([]Finding, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []Finding
	for k, v := range r.s.findings {
		if k.Scope == sc && k.ID == detector {
			out = append(out, cloneFinding(v))
		}
	}
	slices.SortFunc(out, func(a, b Finding) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutFinding(v Finding) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.detectors[detectorKey{v.Scope, v.DetectorID}]; !ok {
		return ErrNotFound
	}
	if v.SampleRevision != "" || v.Observation.Type == "" {
		v.Observation = Observation{}
	}
	w.s.findings[childKey{detectorKey{v.Scope, v.DetectorID}, v.ID}] = cloneFinding(v)
	return nil
}
func (w memoryWriter) DeleteFinding(sc Scope, detector, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.findings, childKey{detectorKey{sc, detector}, id})
	for k := range w.s.exports {
		if k.detectorKey == (detectorKey{sc, detector}) && k.FindingID == id {
			delete(w.s.exports, k)
		}
	}
	return nil
}
func (r memoryReader) Filter(sc Scope, detector, name string) (Filter, error) {
	if err := r.t.Check(false); err != nil {
		return Filter{}, err
	}
	v, ok := r.s.filters[childKey{detectorKey{sc, detector}, name}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneFilter(v), nil
}
func (r memoryReader) Filters(sc Scope, detector string) ([]Filter, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []Filter
	for k, v := range r.s.filters {
		if k.Scope == sc && k.ID == detector {
			out = append(out, cloneFilter(v))
		}
	}
	slices.SortFunc(out, func(a, b Filter) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (w memoryWriter) PutFilter(v Filter) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.detectors[detectorKey{v.Scope, v.DetectorID}]; !ok {
		return ErrNotFound
	}
	w.s.filters[childKey{detectorKey{v.Scope, v.DetectorID}, v.Name}] = cloneFilter(v)
	return nil
}
func (w memoryWriter) DeleteFilter(sc Scope, detector, name string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.filters, childKey{detectorKey{sc, detector}, name})
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
