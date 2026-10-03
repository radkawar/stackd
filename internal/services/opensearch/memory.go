package opensearch

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type memoryState struct {
	domains map[Key]Domain
}

type MemoryRepository struct {
	store *memory.Store[memoryState]
}

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{store: memory.New(domain, memoryState{domains: map[Key]Domain{}}, func(v memoryState) memoryState {
		return memoryState{domains: maps.Clone(v.domains)}
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

func cloneDomain(v Domain) Domain {
	v.AdvancedOptions = maps.Clone(v.AdvancedOptions)
	v.PolicyPrincipals = maps.Clone(v.PolicyPrincipals)
	v.Tags = maps.Clone(v.Tags)
	return v
}

func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name))
}

func (r memoryReader) Domain(k Key) (Domain, error) {
	if err := r.tx.Check(false); err != nil {
		return Domain{}, err
	}
	v, ok := r.s.domains[k]
	if !ok {
		return Domain{}, ErrNotFound
	}
	return cloneDomain(v), nil
}

func (r memoryReader) Domains(scope Scope) ([]Domain, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Domain{}
	for k, v := range r.s.domains {
		if k.Scope == scope {
			out = append(out, cloneDomain(v))
		}
	}
	slices.SortFunc(out, func(a, b Domain) int { return compareKey(a.Key, b.Key) })
	return out, nil
}

func (r memoryReader) AllDomains() ([]Domain, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(r.s.domains))
	for _, v := range r.s.domains {
		out = append(out, cloneDomain(v))
	}
	slices.SortFunc(out, func(a, b Domain) int { return compareKey(a.Key, b.Key) })
	return out, nil
}

func (w memoryWriter) PutDomain(v Domain) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.domains[v.Key] = cloneDomain(v)
	return nil
}

func (w memoryWriter) DeleteDomain(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.domains, k)
	return nil
}

var (
	_ Repository  = (*MemoryRepository)(nil)
	_ Transaction = memoryWriter{}
)
