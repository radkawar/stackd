package s3tables

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryState struct {
	buckets    map[string]Bucket
	namespaces map[string]Namespace
	tables     map[string]Table
	columns    map[string][]Column
	tags       map[string]Tags
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[string]Bucket{}, map[string]Namespace{}, map[string]Table{}, map[string][]Column{}, map[string]Tags{}}, func(v memoryState) memoryState {
		v.buckets = maps.Clone(v.buckets)
		v.namespaces = maps.Clone(v.namespaces)
		v.tables = maps.Clone(v.tables)
		v.columns = maps.Clone(v.columns)
		v.tags = maps.Clone(v.tags)
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
func (r memoryReader) Bucket(sc Scope, arn string) (Bucket, error) {
	if e := r.t.Check(false); e != nil {
		return Bucket{}, e
	}
	v, ok := r.s.buckets[arn]
	if !ok || v.Scope != sc {
		return Bucket{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Buckets(sc Scope) ([]Bucket, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Bucket{}
	for _, v := range r.s.buckets {
		if v.Scope == sc {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Bucket) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) Namespace(sc Scope, b, n string) (Namespace, error) {
	if e := r.t.Check(false); e != nil {
		return Namespace{}, e
	}
	v, ok := r.s.namespaces[b+"/"+n]
	if !ok || v.Scope != sc {
		return Namespace{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Namespaces(sc Scope, b string) ([]Namespace, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Namespace{}
	for _, v := range r.s.namespaces {
		if v.Scope == sc && v.BucketARN == b {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Namespace) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
func (r memoryReader) Table(sc Scope, b, n, name string) (Table, error) {
	if e := r.t.Check(false); e != nil {
		return Table{}, e
	}
	for _, v := range r.s.tables {
		if v.Scope == sc && v.BucketARN == b && v.Namespace == n && v.Name == name && !v.Deleted {
			return v, nil
		}
	}
	return Table{}, ErrNotFound
}
func (r memoryReader) TableByARN(sc Scope, arn string) (Table, error) {
	if e := r.t.Check(false); e != nil {
		return Table{}, e
	}
	v, ok := r.s.tables[arn]
	if !ok || v.Scope != sc || v.Deleted {
		return Table{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) ResourceTags(sc Scope, arn string) (Tags, error) {
	if _, e := r.Bucket(sc, arn); e != nil {
		if _, e = r.TableByARN(sc, arn); e != nil {
			return nil, e
		}
	}
	return maps.Clone(r.s.tags[arn]), nil
}
func (w memoryWriter) PutResourceTags(sc Scope, arn string, tags Tags) error {
	if _, e := w.ResourceTags(sc, arn); e != nil {
		return e
	}
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.tags[arn] = maps.Clone(tags)
	return nil
}
func (r memoryReader) TableColumns(sc Scope, arn string) ([]Column, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	v, ok := r.s.tables[arn]
	if !ok || v.Scope != sc || v.Deleted {
		return nil, ErrNotFound
	}
	return slices.Clone(r.s.columns[arn]), nil
}
func (r memoryReader) Tables(sc Scope, b string) ([]Table, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Table{}
	for _, v := range r.s.tables {
		if v.Scope == sc && v.BucketARN == b && !v.Deleted {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Table) int {
		if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out, nil
}
func (r memoryReader) Warehouse(sc Scope, warehouse string) (Table, error) {
	if e := r.t.Check(false); e != nil {
		return Table{}, e
	}
	for _, v := range r.s.tables {
		if v.Scope == sc && v.Warehouse == warehouse {
			return v, nil
		}
	}
	return Table{}, ErrNotFound
}
func (r memoryReader) PendingTables() ([]Table, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Table{}
	for _, v := range r.s.tables {
		if v.Deleted && !v.Purged {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Table) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutBucket(v Bucket) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.buckets[v.ARN] = v
	return nil
}
func (w memoryWriter) DeleteBucket(sc Scope, arn string) error {
	if _, e := w.Bucket(sc, arn); e != nil {
		return e
	}
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.buckets, arn)
	delete(w.s.tags, arn)
	return nil
}
func (w memoryWriter) PutNamespace(v Namespace) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.namespaces[v.BucketARN+"/"+v.Name] = v
	return nil
}
func (w memoryWriter) DeleteNamespace(sc Scope, b, n string) error {
	if _, e := w.Namespace(sc, b, n); e != nil {
		return e
	}
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.namespaces, b+"/"+n)
	return nil
}
func (w memoryWriter) PutTable(v Table) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.tables[v.ARN] = v
	if v.Deleted {
		delete(w.s.tags, v.ARN)
	}
	return nil
}
func (w memoryWriter) PutTableColumns(sc Scope, arn string, columns []Column) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	v, ok := w.s.tables[arn]
	if !ok || v.Scope != sc || v.Deleted {
		return ErrNotFound
	}
	w.s.columns[arn] = slices.Clone(columns)
	return nil
}
func (w memoryWriter) DeleteTable(sc Scope, b, n, name string) error {
	v, e := w.Table(sc, b, n, name)
	if e != nil {
		return e
	}
	v.Deleted = true
	return w.PutTable(v)
}
