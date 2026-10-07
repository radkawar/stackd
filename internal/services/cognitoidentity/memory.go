package cognitoidentity

import (
	"cmp"
	"context"
	"maps"
	"slices"

	api "stackd/internal/awsapi/cognitoidentity"
	"stackd/storage/memory"
)

type regionalID struct{ partition, region, id string }
type loginKey struct {
	pool  PoolKey
	login Login
}
type memoryState struct {
	pools      map[PoolKey]PoolRecord
	poolIDs    map[regionalID]PoolKey
	identities map[regionalID]IdentityRecord
	logins     map[loginKey]regionalID
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	state := memoryState{map[PoolKey]PoolRecord{}, map[regionalID]PoolKey{}, map[regionalID]IdentityRecord{}, map[loginKey]regionalID{}}
	return &MemoryRepository{memory.New(d, state, func(s memoryState) memoryState {
		s.pools = maps.Clone(s.pools)
		s.poolIDs = maps.Clone(s.poolIDs)
		s.identities = maps.Clone(s.identities)
		s.logins = maps.Clone(s.logins)
		return s
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
func clonePool(v PoolRecord) PoolRecord {
	v.Providers = api.CloneCognitoIdentityProviderList(v.Providers)
	v.Tags = maps.Clone(v.Tags)
	v.Roles = maps.Clone(v.Roles)
	v.Mappings = api.CloneRoleMappingMap(v.Mappings)
	v.PrincipalTagMaps = maps.Clone(v.PrincipalTagMaps)
	for provider, mapping := range v.PrincipalTagMaps {
		mapping.Tags = maps.Clone(mapping.Tags)
		v.PrincipalTagMaps[provider] = mapping
	}
	return v
}
func cloneIdentity(v IdentityRecord) IdentityRecord { v.Logins = slices.Clone(v.Logins); return v }
func (r memoryReader) Pool(k PoolKey) (PoolRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return PoolRecord{}, e
	}
	v, ok := r.s.pools[k]
	if !ok {
		return PoolRecord{}, ErrNotFound
	}
	return clonePool(v), nil
}
func (r memoryReader) PoolByID(p, g, id string) (PoolRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return PoolRecord{}, e
	}
	k, ok := r.s.poolIDs[regionalID{p, g, id}]
	if !ok {
		return PoolRecord{}, ErrNotFound
	}
	return r.Pool(k)
}
func (r memoryReader) Pools(scope Scope) ([]PoolRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []PoolRecord{}
	for k, v := range r.s.pools {
		if k.Scope == scope {
			out = append(out, clonePool(v))
		}
	}
	slices.SortFunc(out, func(a, b PoolRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) PoolByOwner(scope Scope, owner ResourceOwner) (PoolRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return PoolRecord{}, e
	}
	for k, v := range r.s.pools {
		if k.Scope == scope && owner.Token != "" && v.Owner == owner {
			return clonePool(v), nil
		}
	}
	return PoolRecord{}, ErrNotFound
}
func (r memoryReader) Identity(p, g, id string) (IdentityRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return IdentityRecord{}, e
	}
	v, ok := r.s.identities[regionalID{p, g, id}]
	if !ok {
		return IdentityRecord{}, ErrNotFound
	}
	return cloneIdentity(v), nil
}
func (r memoryReader) IdentityByLogin(pool PoolKey, l Login) (IdentityRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return IdentityRecord{}, e
	}
	k, ok := r.s.logins[loginKey{pool, l}]
	if !ok {
		return IdentityRecord{}, ErrNotFound
	}
	return r.Identity(k.partition, k.region, k.id)
}
func (r memoryReader) Identities(pool PoolKey) ([]IdentityRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []IdentityRecord{}
	for _, v := range r.s.identities {
		if v.Pool == pool {
			out = append(out, cloneIdentity(v))
		}
	}
	slices.SortFunc(out, func(a, b IdentityRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutPool(v PoolRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	// The owner claim is written with a new row; upserts never rewrite it.
	if prior, ok := w.s.pools[v.Key]; ok {
		v.Owner = prior.Owner
	}
	w.s.pools[v.Key] = clonePool(v)
	w.s.poolIDs[regionalID{v.Key.Partition, v.Key.Region, v.Key.ID}] = v.Key
	return nil
}
func (w memoryWriter) DeletePool(k PoolKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	for id, v := range w.s.identities {
		if v.Pool == k {
			if e := w.DeleteIdentity(id.partition, id.region, id.id); e != nil {
				return e
			}
		}
	}
	delete(w.s.pools, k)
	delete(w.s.poolIDs, regionalID{k.Partition, k.Region, k.ID})
	return nil
}
func (w memoryWriter) PutIdentity(v IdentityRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	k := regionalID{v.Pool.Partition, v.Pool.Region, v.ID}
	for _, l := range v.Logins {
		if prior, ok := w.s.logins[loginKey{v.Pool, l}]; ok && prior != k {
			return failure("ResourceConflictException", "Login already belongs to another identity.")
		}
	}
	for _, l := range w.s.identities[k].Logins {
		delete(w.s.logins, loginKey{v.Pool, l})
	}
	w.s.identities[k] = cloneIdentity(v)
	for _, l := range v.Logins {
		w.s.logins[loginKey{v.Pool, l}] = k
	}
	return nil
}
func (w memoryWriter) DeleteIdentity(p, g, id string) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	k := regionalID{p, g, id}
	v := w.s.identities[k]
	for _, l := range v.Logins {
		delete(w.s.logins, loginKey{v.Pool, l})
	}
	delete(w.s.identities, k)
	return nil
}
