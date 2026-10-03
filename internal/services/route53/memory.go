package route53

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryState struct {
	zones   map[string]Zone
	changes map[string]Change
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[string]Zone{}, map[string]Change{}}, func(s memoryState) memoryState {
		s.zones = maps.Clone(s.zones)
		s.changes = maps.Clone(s.changes)
		return s
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
func cloneZone(z Zone) Zone {
	z.Records = slices.Clone(z.Records)
	for i := range z.Records {
		z.Records[i].Values = slices.Clone(z.Records[i].Values)
		if a := z.Records[i].Alias; a != nil {
			v := *a
			z.Records[i].Alias = &v
		}
	}
	return z
}
func (r memoryReader) Zone(id string) (Zone, error) {
	if e := r.t.Check(false); e != nil {
		return Zone{}, e
	}
	z, ok := r.s.zones[id]
	if !ok {
		return Zone{}, ErrNotFound
	}
	return cloneZone(z), nil
}
func (r memoryReader) Zones() ([]Zone, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Zone, 0, len(r.s.zones))
	for _, z := range r.s.zones {
		out = append(out, cloneZone(z))
	}
	slices.SortFunc(out, func(a, b Zone) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Change(id string) (Change, error) {
	if e := r.t.Check(false); e != nil {
		return Change{}, e
	}
	c, ok := r.s.changes[id]
	if !ok {
		return Change{}, ErrNotFound
	}
	return c, nil
}
func (w memoryWriter) PutZone(z Zone) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.zones[z.ID] = cloneZone(z)
	return nil
}
func (w memoryWriter) DeleteZone(id string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.zones, id)
	return nil
}
func (w memoryWriter) PutChange(c Change) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.changes[c.ID] = c
	return nil
}
