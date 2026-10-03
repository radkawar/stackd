package rds

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryState struct {
	databases       map[Key]Database
	snapshots       map[Key]Snapshot
	parameterGroups map[Key]ParameterGroup
	subnetGroups    map[Key]SubnetGroup
}
type MemoryRepository struct {
	store *memory.Store[memoryState]
}

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, memoryState{map[Key]Database{}, map[Key]Snapshot{}, map[Key]ParameterGroup{}, map[Key]SubnetGroup{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.databases), maps.Clone(v.snapshots), maps.Clone(v.parameterGroups), maps.Clone(v.subnetGroups)}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryReader{v, tx})
	})
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{v, tx}})
	})
}

func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(v *memoryState, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{v, tx}})
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

func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
}

func cloneDatabase(v Database) Database {
	v.Ciphertext = slices.Clone(v.Ciphertext)
	v.PendingCiphertext = slices.Clone(v.PendingCiphertext)
	v.Parameters = maps.Clone(v.Parameters)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func cloneSnapshot(v Snapshot) Snapshot {
	v.Ciphertext = slices.Clone(v.Ciphertext)
	v.Parameters = maps.Clone(v.Parameters)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func cloneParameterGroup(v ParameterGroup) ParameterGroup {
	v.Parameters = maps.Clone(v.Parameters)
	v.ApplyMethods = maps.Clone(v.ApplyMethods)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func cloneSubnetGroup(v SubnetGroup) SubnetGroup {
	v.Subnets = slices.Clone(v.Subnets)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func (r memoryReader) Database(k Key) (Database, error) {
	if err := r.tx.Check(false); err != nil {
		return Database{}, err
	}
	v, ok := r.s.databases[k]
	if !ok {
		return Database{}, ErrNotFound
	}
	return cloneDatabase(v), nil
}

func (r memoryReader) Databases(scope Scope) ([]Database, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Database{}
	for k, v := range r.s.databases {
		if k.Scope == scope {
			out = append(out, cloneDatabase(v))
		}
	}
	slices.SortFunc(out, func(a, b Database) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (w memoryWriter) PutDatabase(v Database) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.databases[v.Key] = cloneDatabase(v)
	return nil
}

func (w memoryWriter) DeleteDatabase(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.databases, k)
	return nil
}

func (r memoryReader) AllDatabases() ([]Database, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Database, 0, len(r.s.databases))
	for _, v := range r.s.databases {
		out = append(out, cloneDatabase(v))
	}
	slices.SortFunc(out, func(a, b Database) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (r memoryReader) Snapshot(k Key) (Snapshot, error) {
	if err := r.tx.Check(false); err != nil {
		return Snapshot{}, err
	}
	v, ok := r.s.snapshots[k]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	return cloneSnapshot(v), nil
}

func (r memoryReader) Snapshots(scope Scope) ([]Snapshot, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Snapshot{}
	for k, v := range r.s.snapshots {
		if k.Scope == scope {
			out = append(out, cloneSnapshot(v))
		}
	}
	slices.SortFunc(out, func(a, b Snapshot) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (w memoryWriter) PutSnapshot(v Snapshot) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.snapshots[v.Key] = cloneSnapshot(v)
	return nil
}

func (w memoryWriter) DeleteSnapshot(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.snapshots, k)
	return nil
}

func (r memoryReader) AllSnapshots() ([]Snapshot, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(r.s.snapshots))
	for _, v := range r.s.snapshots {
		out = append(out, cloneSnapshot(v))
	}
	slices.SortFunc(out, func(a, b Snapshot) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (r memoryReader) ParameterGroup(k Key) (ParameterGroup, error) {
	if err := r.tx.Check(false); err != nil {
		return ParameterGroup{}, err
	}
	v, ok := r.s.parameterGroups[k]
	if !ok {
		return ParameterGroup{}, ErrNotFound
	}
	return cloneParameterGroup(v), nil
}

func (r memoryReader) ParameterGroups(scope Scope) ([]ParameterGroup, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ParameterGroup{}
	for k, v := range r.s.parameterGroups {
		if k.Scope == scope {
			out = append(out, cloneParameterGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b ParameterGroup) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (w memoryWriter) PutParameterGroup(v ParameterGroup) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.parameterGroups[v.Key] = cloneParameterGroup(v)
	return nil
}

func (w memoryWriter) DeleteParameterGroup(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.parameterGroups, k)
	return nil
}

func (r memoryReader) SubnetGroup(k Key) (SubnetGroup, error) {
	if err := r.tx.Check(false); err != nil {
		return SubnetGroup{}, err
	}
	v, ok := r.s.subnetGroups[k]
	if !ok {
		return SubnetGroup{}, ErrNotFound
	}
	return cloneSubnetGroup(v), nil
}

func (r memoryReader) SubnetGroups(scope Scope) ([]SubnetGroup, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SubnetGroup{}
	for k, v := range r.s.subnetGroups {
		if k.Scope == scope {
			out = append(out, cloneSubnetGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b SubnetGroup) int {
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}

func (w memoryWriter) PutSubnetGroup(v SubnetGroup) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.subnetGroups[v.Key] = cloneSubnetGroup(v)
	return nil
}

func (w memoryWriter) DeleteSubnetGroup(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.subnetGroups, k)
	return nil
}
