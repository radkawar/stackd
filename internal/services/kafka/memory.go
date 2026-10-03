package kafka

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type revisionKey struct {
	ARN      string
	Revision int64
}
type memoryState struct {
	clusters       map[string]ClusterRecord
	configurations map[string]ConfigurationRecord
	revisions      map[revisionKey]RevisionRecord
	operations     map[string]OperationRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[string]ClusterRecord{}, map[string]ConfigurationRecord{}, map[revisionKey]RevisionRecord{}, map[string]OperationRecord{}}, func(v memoryState) memoryState {
		v.clusters = maps.Clone(v.clusters)
		v.configurations = maps.Clone(v.configurations)
		v.revisions = maps.Clone(v.revisions)
		v.operations = maps.Clone(v.operations)
		return v
	})}
}
func (m *MemoryRepository) View(c context.Context, f func(Reader) error) error {
	return m.store.View(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryReader{s, t}) })
}
func (m *MemoryRepository) Update(c context.Context, f func(Transaction) error) error {
	return m.store.Update(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}
func (m *MemoryRepository) Attempt(c context.Context, f func(Transaction) error) error {
	return m.store.Attempt(c, func(s *memoryState, t *memory.Transaction) error { return f(memoryWriter{memoryReader{s, t}}) })
}

type memoryReader struct {
	s *memoryState
	t *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.t.Context() }
func cloneCluster(v ClusterRecord) ClusterRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Secrets = slices.Clone(v.Secrets)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	v.Endpoint.Brokers = slices.Clone(v.Endpoint.Brokers)
	v.Endpoint.CAPEM = slices.Clone(v.Endpoint.CAPEM)
	return v
}
func cloneConfiguration(v ConfigurationRecord) ConfigurationRecord {
	v.KafkaVersions = slices.Clone(v.KafkaVersions)
	return v
}
func cloneRevision(v RevisionRecord) RevisionRecord    { return v }
func cloneOperation(v OperationRecord) OperationRecord { return v }
func (r memoryReader) Cluster(arn string) (ClusterRecord, error) {
	if e := r.t.Check(false); e != nil {
		return ClusterRecord{}, e
	}
	v, ok := r.s.clusters[arn]
	if !ok {
		return ClusterRecord{}, ErrNotFound
	}
	return cloneCluster(v), nil
}
func (w memoryWriter) PutCluster(v ClusterRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.clusters[v.ARN] = cloneCluster(v)
	return nil
}
func (r memoryReader) Configuration(arn string) (ConfigurationRecord, error) {
	if e := r.t.Check(false); e != nil {
		return ConfigurationRecord{}, e
	}
	v, ok := r.s.configurations[arn]
	if !ok {
		return ConfigurationRecord{}, ErrNotFound
	}
	return cloneConfiguration(v), nil
}
func (w memoryWriter) PutConfiguration(v ConfigurationRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.configurations[v.ARN] = cloneConfiguration(v)
	return nil
}
func (r memoryReader) Revision(arn string, revision int64) (RevisionRecord, error) {
	if e := r.t.Check(false); e != nil {
		return RevisionRecord{}, e
	}
	v, ok := r.s.revisions[revisionKey{arn, revision}]
	if !ok {
		return RevisionRecord{}, ErrNotFound
	}
	return cloneRevision(v), nil
}
func (w memoryWriter) PutRevision(v RevisionRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.revisions[revisionKey{v.ARN, v.Revision}] = cloneRevision(v)
	return nil
}
func (r memoryReader) Operation(arn string) (OperationRecord, error) {
	if e := r.t.Check(false); e != nil {
		return OperationRecord{}, e
	}
	v, ok := r.s.operations[arn]
	if !ok {
		return OperationRecord{}, ErrNotFound
	}
	return cloneOperation(v), nil
}
func (w memoryWriter) PutOperation(v OperationRecord) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.operations[v.ARN] = cloneOperation(v)
	return nil
}
func (r memoryReader) AllClusters() ([]ClusterRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []ClusterRecord{}
	for _, v := range r.s.clusters {
		out = append(out, cloneCluster(v))
	}
	slices.SortFunc(out, func(a, b ClusterRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) Clusters(sc Scope) ([]ClusterRecord, error) {
	all, e := r.AllClusters()
	if e != nil {
		return nil, e
	}
	out := []ClusterRecord{}
	for _, v := range all {
		if v.Scope == sc {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r memoryReader) Configurations(sc Scope) ([]ConfigurationRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []ConfigurationRecord{}
	for _, v := range r.s.configurations {
		if v.Scope == sc {
			out = append(out, cloneConfiguration(v))
		}
	}
	slices.SortFunc(out, func(a, b ConfigurationRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) Revisions(arn string) ([]RevisionRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []RevisionRecord{}
	for _, v := range r.s.revisions {
		if v.ARN == arn {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b RevisionRecord) int { return cmp.Compare(a.Revision, b.Revision) })
	return out, nil
}
func (r memoryReader) Operations(arn string) ([]OperationRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []OperationRecord{}
	for _, v := range r.s.operations {
		if v.ClusterARN == arn {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b OperationRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) DeleteCluster(arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.clusters, arn)
	return nil
}
func (w memoryWriter) DeleteConfiguration(arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.configurations, arn)
	for k := range w.s.revisions {
		if k.ARN == arn {
			delete(w.s.revisions, k)
		}
	}
	return nil
}
