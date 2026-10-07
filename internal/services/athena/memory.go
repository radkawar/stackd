package athena

import (
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	workgroups map[ResourceKey]WorkGroupRecord
	catalogs   map[ResourceKey]CatalogRecord
	named      map[ResourceKey]NamedQueryRecord
	prepared   map[StatementKey]PreparedStatementRecord
	queries    map[ResourceKey]QueryRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{workgroups: map[ResourceKey]WorkGroupRecord{}, catalogs: map[ResourceKey]CatalogRecord{}, named: map[ResourceKey]NamedQueryRecord{}, prepared: map[StatementKey]PreparedStatementRecord{}, queries: map[ResourceKey]QueryRecord{}}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		v.workgroups = maps.Clone(v.workgroups)
		v.catalogs = maps.Clone(v.catalogs)
		v.named = maps.Clone(v.named)
		v.prepared = maps.Clone(v.prepared)
		v.queries = maps.Clone(v.queries)
		return v
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
func cloneWorkGroup(v WorkGroupRecord) WorkGroupRecord {
	v.Data = api.CloneWorkGroup(v.Data)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) WorkGroup(key ResourceKey) (WorkGroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return WorkGroupRecord{}, err
	}
	v, ok := r.s.workgroups[key]
	if !ok {
		return WorkGroupRecord{}, ErrNotFound
	}
	return cloneWorkGroup(v), nil
}
func (r memoryReader) WorkGroups(q ResourceQuery) ([]WorkGroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []WorkGroupRecord{}
	for _, v := range r.s.workgroups {
		if v.Key.Scope == q.Scope && v.Key.Name > q.After {
			out = append(out, cloneWorkGroup(v))
		}
	}
	slices.SortFunc(out, func(a, b WorkGroupRecord) int {
		if a.Key.Name < b.Key.Name {
			return -1
		}
		if a.Key.Name > b.Key.Name {
			return 1
		}
		return 0
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutWorkGroup(v WorkGroupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	// Like the SQLite row, a private claim is immutable while its row exists.
	if old, ok := w.s.workgroups[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.workgroups[v.Key] = cloneWorkGroup(v)
	return nil
}
func (w memoryWriter) DeleteWorkGroup(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for queryKey, query := range w.s.queries {
		if queryKey.Scope == key.Scope && value(query.Data.WorkGroup) == key.Name {
			delete(w.s.queries, queryKey)
		}
	}
	delete(w.s.workgroups, key)
	return nil
}
func cloneCatalog(v CatalogRecord) CatalogRecord {
	v.Data = api.CloneDataCatalog(v.Data)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func (r memoryReader) Catalog(key ResourceKey) (CatalogRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return CatalogRecord{}, err
	}
	v, ok := r.s.catalogs[key]
	if !ok {
		return CatalogRecord{}, ErrNotFound
	}
	return cloneCatalog(v), nil
}
func (r memoryReader) Catalogs(q ResourceQuery) ([]CatalogRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CatalogRecord{}
	for _, v := range r.s.catalogs {
		if v.Key.Scope == q.Scope && v.Key.Name > q.After {
			out = append(out, cloneCatalog(v))
		}
	}
	slices.SortFunc(out, func(a, b CatalogRecord) int {
		if a.Key.Name < b.Key.Name {
			return -1
		}
		if a.Key.Name > b.Key.Name {
			return 1
		}
		return 0
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutCatalog(v CatalogRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if old, ok := w.s.catalogs[v.Key]; ok {
		v.CFNOwner = old.CFNOwner
	}
	w.s.catalogs[v.Key] = cloneCatalog(v)
	return nil
}
func (w memoryWriter) DeleteCatalog(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.catalogs, key)
	return nil
}
func cloneNamedQuery(v NamedQueryRecord) NamedQueryRecord {
	v.Data = api.CloneNamedQuery(v.Data)
	return v
}
func (r memoryReader) NamedQuery(key ResourceKey) (NamedQueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return NamedQueryRecord{}, err
	}
	v, ok := r.s.named[key]
	if !ok {
		return NamedQueryRecord{}, ErrNotFound
	}
	return cloneNamedQuery(v), nil
}
func (r memoryReader) NamedQueries(q ResourceQuery) ([]NamedQueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []NamedQueryRecord{}
	for _, v := range r.s.named {
		if v.Key.Scope == q.Scope && v.Key.Name > q.After && (q.WorkGroup == "" || value(v.Data.WorkGroup) == q.WorkGroup) {
			out = append(out, cloneNamedQuery(v))
		}
	}
	slices.SortFunc(out, func(a, b NamedQueryRecord) int {
		if a.Key.Name < b.Key.Name {
			return -1
		}
		if a.Key.Name > b.Key.Name {
			return 1
		}
		return 0
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutNamedQuery(v NamedQueryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.named[v.Key] = cloneNamedQuery(v)
	return nil
}
func (w memoryWriter) DeleteNamedQuery(key ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.named, key)
	return nil
}
func (r memoryReader) NamedQueryByToken(scope Scope, token string) (NamedQueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return NamedQueryRecord{}, err
	}
	for _, v := range r.s.named {
		if v.Key.Scope == scope && v.Token == token && token != "" {
			return cloneNamedQuery(v), nil
		}
	}
	return NamedQueryRecord{}, ErrNotFound
}
func clonePreparedStatement(v PreparedStatementRecord) PreparedStatementRecord {
	v.Data = api.ClonePreparedStatement(v.Data)
	return v
}
func (r memoryReader) PreparedStatement(key StatementKey) (PreparedStatementRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PreparedStatementRecord{}, err
	}
	v, ok := r.s.prepared[key]
	if !ok {
		return PreparedStatementRecord{}, ErrNotFound
	}
	return clonePreparedStatement(v), nil
}
func (r memoryReader) PreparedStatements(q ResourceQuery) ([]PreparedStatementRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []PreparedStatementRecord{}
	for _, v := range r.s.prepared {
		if v.Key.WorkGroup.Scope == q.Scope && v.Key.Name > q.After && v.Key.WorkGroup.Name == q.WorkGroup {
			out = append(out, clonePreparedStatement(v))
		}
	}
	slices.SortFunc(out, func(a, b PreparedStatementRecord) int {
		if a.Key.Name < b.Key.Name {
			return -1
		}
		if a.Key.Name > b.Key.Name {
			return 1
		}
		return 0
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutPreparedStatement(v PreparedStatementRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.prepared[v.Key] = clonePreparedStatement(v)
	return nil
}
func (w memoryWriter) DeletePreparedStatement(key StatementKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.prepared, key)
	return nil
}
func cloneQuery(v QueryRecord) QueryRecord {
	v.Data = api.CloneQueryExecution(v.Data)
	v.Caller = awsctx.Clone(v.Caller)
	v.Columns = slices.Clone(v.Columns)
	for i := range v.Columns {
		v.Columns[i] = api.CloneColumnInfo(v.Columns[i])
	}
	if v.Started != nil {
		t := *v.Started
		v.Started = &t
	}
	return v
}
func (r memoryReader) Query(key ResourceKey) (QueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return QueryRecord{}, err
	}
	v, ok := r.s.queries[key]
	if !ok {
		return QueryRecord{}, ErrNotFound
	}
	return cloneQuery(v), nil
}
func (r memoryReader) Queries(q ResourceQuery) ([]QueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []QueryRecord{}
	for _, v := range r.s.queries {
		if v.Key.Scope == q.Scope && v.Key.Name > q.After && (q.WorkGroup == "" || value(v.Data.WorkGroup) == q.WorkGroup) {
			out = append(out, cloneQuery(v))
		}
	}
	slices.SortFunc(out, func(a, b QueryRecord) int {
		if a.Key.Name < b.Key.Name {
			return -1
		}
		if a.Key.Name > b.Key.Name {
			return 1
		}
		return 0
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	return out, nil
}
func (w memoryWriter) PutQuery(v QueryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.queries[v.Key] = cloneQuery(v)
	return nil
}
func (r memoryReader) QueryByToken(scope Scope, token string) (QueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return QueryRecord{}, err
	}
	for _, v := range r.s.queries {
		if v.Key.Scope == scope && v.Token == token && token != "" {
			return cloneQuery(v), nil
		}
	}
	return QueryRecord{}, ErrNotFound
}
func compareQueryKeys(a, b ResourceKey) int {
	if a.Name != b.Name {
		return strings.Compare(a.Name, b.Name)
	}
	if a.Partition != b.Partition {
		return strings.Compare(a.Partition, b.Partition)
	}
	if a.AccountID != b.AccountID {
		return strings.Compare(a.AccountID, b.AccountID)
	}
	return strings.Compare(a.Region, b.Region)
}
func (r memoryReader) NextQuery() (QueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return QueryRecord{}, err
	}
	var selected QueryRecord
	for _, v := range r.s.queries {
		state := queryState(v)
		if state != "QUEUED" && !((state == "CANCELLED" || state == "FAILED") && v.EngineID != "") {
			continue
		}
		if selected.Key.Name == "" || v.Due.Before(selected.Due) || v.Due.Equal(selected.Due) && compareQueryKeys(v.Key, selected.Key) < 0 {
			selected = v
		}
	}
	if selected.Key.Name == "" {
		return QueryRecord{}, ErrNotFound
	}
	return cloneQuery(selected), nil
}
func (r memoryReader) ActiveQueries() ([]QueryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []QueryRecord{}
	for _, v := range r.s.queries {
		if queryState(v) == "RUNNING" || queryState(v) == "QUEUED" || v.EngineID != "" {
			out = append(out, cloneQuery(v))
		}
	}
	slices.SortFunc(out, func(a, b QueryRecord) int { return compareQueryKeys(a.Key, b.Key) })
	return out, nil
}

var _ Repository = (*MemoryRepository)(nil)
