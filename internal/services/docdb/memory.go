package docdb

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryState struct {
	clusters  map[Key]Cluster
	instances map[Key]Instance
	snapshots map[Key]Snapshot
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, memoryState{map[Key]Cluster{}, map[Key]Instance{}, map[Key]Snapshot{}}, func(s memoryState) memoryState {
		return memoryState{maps.Clone(s.clusters), maps.Clone(s.instances), maps.Clone(s.snapshots)}
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
func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
}
func cloneCluster(v Cluster) Cluster {
	v.Tags = maps.Clone(v.Tags)
	v.Ciphertext = slices.Clone(v.Ciphertext)
	v.PendingCiphertext = slices.Clone(v.PendingCiphertext)
	v.Endpoint.CA = slices.Clone(v.Endpoint.CA)
	return v
}
func cloneInstance(v Instance) Instance { v.Tags = maps.Clone(v.Tags); return v }
func cloneSnapshot(v Snapshot) Snapshot {
	v.Tags = maps.Clone(v.Tags)
	v.Ciphertext = slices.Clone(v.Ciphertext)
	return v
}
func (r memoryReader) Cluster(k Key) (Cluster, error) {
	if e := r.tx.Check(false); e != nil {
		return Cluster{}, e
	}
	v, ok := r.s.clusters[k]
	if !ok {
		return Cluster{}, ErrNotFound
	}
	return cloneCluster(v), nil
}
func (r memoryReader) Instance(k Key) (Instance, error) {
	if e := r.tx.Check(false); e != nil {
		return Instance{}, e
	}
	v, ok := r.s.instances[k]
	if !ok {
		return Instance{}, ErrNotFound
	}
	return cloneInstance(v), nil
}
func (r memoryReader) Snapshot(k Key) (Snapshot, error) {
	if e := r.tx.Check(false); e != nil {
		return Snapshot{}, e
	}
	v, ok := r.s.snapshots[k]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	return cloneSnapshot(v), nil
}
func (r memoryReader) Clusters() ([]Cluster, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := make([]Cluster, 0, len(r.s.clusters))
	for _, v := range r.s.clusters {
		out = append(out, cloneCluster(v))
	}
	slices.SortFunc(out, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) Instances() ([]Instance, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := make([]Instance, 0, len(r.s.instances))
	for _, v := range r.s.instances {
		out = append(out, cloneInstance(v))
	}
	slices.SortFunc(out, func(a, b Instance) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) Snapshots() ([]Snapshot, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := make([]Snapshot, 0, len(r.s.snapshots))
	for _, v := range r.s.snapshots {
		out = append(out, cloneSnapshot(v))
	}
	slices.SortFunc(out, func(a, b Snapshot) int { return compareKey(a.Key, b.Key) })
	return out, nil
}
func (w memoryWriter) PutCluster(v Cluster) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.clusters[v.Key] = cloneCluster(v)
	return nil
}
func (w memoryWriter) PutInstance(v Instance) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.instances[v.Key] = cloneInstance(v)
	return nil
}
func (w memoryWriter) PutSnapshot(v Snapshot) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.snapshots[v.Key] = cloneSnapshot(v)
	return nil
}
func (w memoryWriter) DeleteCluster(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.clusters, k)
	return nil
}
func (w memoryWriter) DeleteInstance(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.instances, k)
	return nil
}
func (w memoryWriter) DeleteSnapshot(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.snapshots, k)
	return nil
}
