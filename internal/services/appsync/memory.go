package appsync

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/appsync"
	"stackd/storage/memory"
)

type childKey struct {
	API  Key
	Name string
}
type memoryState struct {
	apis        map[Key]APIRecord
	datasources map[childKey]DataSourceRecord
	resolvers   map[childKey]ResolverRecord
	functions   map[childKey]FunctionRecord
	apikeys     map[childKey]APIKeyRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{apis: map[Key]APIRecord{},
		datasources: map[childKey]DataSourceRecord{},
		resolvers:   map[childKey]ResolverRecord{},
		functions:   map[childKey]FunctionRecord{},
		apikeys:     map[childKey]APIKeyRecord{},
	}, func(s memoryState) memoryState {
		s.apis = maps.Clone(s.apis)
		s.datasources = maps.Clone(s.datasources)
		s.resolvers = maps.Clone(s.resolvers)
		s.functions = maps.Clone(s.functions)
		s.apikeys = maps.Clone(s.apikeys)
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
func cloneAPI(p APIRecord) APIRecord {
	p.API = api.CloneGraphqlApi(p.API)
	p.SchemaDetails = slices.Clone(p.SchemaDetails)
	return p
}
func (r memoryReader) API(k Key) (APIRecord, error) {
	if e := r.t.Check(false); e != nil {
		return APIRecord{}, e
	}
	p, ok := r.s.apis[k]
	if !ok {
		return APIRecord{}, ErrNotFound
	}
	return cloneAPI(p), nil
}
func (r memoryReader) APIByID(id string) (APIRecord, error) {
	if e := r.t.Check(false); e != nil {
		return APIRecord{}, e
	}
	for _, p := range r.s.apis {
		if p.Key.ID == id {
			return cloneAPI(p), nil
		}
	}
	return APIRecord{}, ErrNotFound
}
func (r memoryReader) APIs() ([]APIRecord, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []APIRecord{}
	for _, p := range r.s.apis {
		out = append(out, cloneAPI(p))
	}
	slices.SortFunc(out, func(a, b APIRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return out, nil
}
func (r memoryWriter) PutAPI(p APIRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	for k := range r.s.apis {
		if k.ID == p.Key.ID && k != p.Key {
			return ErrConflict
		}
	}
	r.s.apis[p.Key] = cloneAPI(p)
	return nil
}
func (r memoryWriter) DeleteAPI(k Key) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if _, e := r.API(k); e != nil {
		return e
	}
	delete(r.s.apis, k)
	for c := range r.s.datasources {
		if c.API == k {
			delete(r.s.datasources, c)
		}
	}
	for c := range r.s.resolvers {
		if c.API == k {
			delete(r.s.resolvers, c)
		}
	}
	for c := range r.s.functions {
		if c.API == k {
			delete(r.s.functions, c)
		}
	}
	for c := range r.s.apikeys {
		if c.API == k {
			delete(r.s.apikeys, c)
		}
	}
	return nil
}
func (r memoryReader) DataSources(k Key) ([]DataSourceRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	out := []DataSourceRecord{}
	for c, p := range r.s.datasources {
		if c.API == k {
			p.DataSource = api.CloneDataSource(p.DataSource)
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b DataSourceRecord) int {
		return cmp.Compare(value(a.DataSource.Name), value(b.DataSource.Name))
	})
	return out, nil
}
func (r memoryWriter) PutDataSource(p DataSourceRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if _, e := r.API(p.API); e != nil {
		return e
	}
	p.DataSource = api.CloneDataSource(p.DataSource)
	r.s.datasources[childKey{p.API, value(p.DataSource.Name)}] = p
	return nil
}
func (r memoryWriter) DeleteDataSource(k Key, name string) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if e := CheckDeleteDataSource(r, k, name); e != nil {
		return e
	}
	c := childKey{k, name}
	if _, ok := r.s.datasources[c]; !ok {
		return ErrNotFound
	}
	delete(r.s.datasources, c)
	return nil
}
func (r memoryReader) Resolvers(k Key) ([]ResolverRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	out := []ResolverRecord{}
	for c, p := range r.s.resolvers {
		if c.API == k {
			p.Resolver = api.CloneResolver(p.Resolver)
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b ResolverRecord) int {
		return cmp.Compare(value(a.Resolver.TypeName)+"."+value(a.Resolver.FieldName), value(b.Resolver.TypeName)+"."+value(b.Resolver.FieldName))
	})
	return out, nil
}
func (r memoryWriter) PutResolver(p ResolverRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if _, e := r.API(p.API); e != nil {
		return e
	}
	if e := CheckResolverReferences(r, p); e != nil {
		return e
	}
	p.Resolver = api.CloneResolver(p.Resolver)
	r.s.resolvers[childKey{p.API, value(p.Resolver.TypeName) + "." + value(p.Resolver.FieldName)}] = p
	return nil
}
func (r memoryWriter) DeleteResolver(k Key, typeName, fieldName string) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	c := childKey{k, typeName + "." + fieldName}
	if _, ok := r.s.resolvers[c]; !ok {
		return ErrNotFound
	}
	delete(r.s.resolvers, c)
	return nil
}
func (r memoryReader) Functions(k Key) ([]FunctionRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	out := []FunctionRecord{}
	for c, p := range r.s.functions {
		if c.API == k {
			p.Function = api.CloneFunctionConfiguration(p.Function)
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b FunctionRecord) int {
		return cmp.Compare(value(a.Function.FunctionId), value(b.Function.FunctionId))
	})
	return out, nil
}
func (r memoryWriter) PutFunction(p FunctionRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if _, e := r.API(p.API); e != nil {
		return e
	}
	if e := CheckFunctionReferences(r, p); e != nil {
		return e
	}
	p.Function = api.CloneFunctionConfiguration(p.Function)
	r.s.functions[childKey{p.API, value(p.Function.FunctionId)}] = p
	return nil
}
func (r memoryWriter) DeleteFunction(k Key, name string) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if e := CheckDeleteFunction(r, k, name); e != nil {
		return e
	}
	c := childKey{k, name}
	if _, ok := r.s.functions[c]; !ok {
		return ErrNotFound
	}
	delete(r.s.functions, c)
	return nil
}
func (r memoryReader) APIKeys(k Key) ([]APIKeyRecord, error) {
	if _, e := r.API(k); e != nil {
		return nil, e
	}
	out := []APIKeyRecord{}
	for c, p := range r.s.apikeys {
		if c.API == k {
			p.Key = api.CloneApiKey(p.Key)
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b APIKeyRecord) int { return cmp.Compare(value(a.Key.Id), value(b.Key.Id)) })
	return out, nil
}
func (r memoryWriter) PutAPIKey(p APIKeyRecord) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	if _, e := r.API(p.API); e != nil {
		return e
	}
	p.Key = api.CloneApiKey(p.Key)
	r.s.apikeys[childKey{p.API, value(p.Key.Id)}] = p
	return nil
}
func (r memoryWriter) DeleteAPIKey(k Key, name string) error {
	if e := r.t.Check(true); e != nil {
		return e
	}
	c := childKey{k, name}
	if _, ok := r.s.apikeys[c]; !ok {
		return ErrNotFound
	}
	delete(r.s.apikeys, c)
	return nil
}
