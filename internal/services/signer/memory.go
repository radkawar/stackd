package signer

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type profileKey struct {
	Scope
	Name, Version string
}
type jobKey struct {
	Scope
	ID string
}
type memoryState struct {
	authorities map[Scope]Authority
	profiles    map[profileKey]Profile
	jobs        map[jobKey]Job
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[Scope]Authority{}, map[profileKey]Profile{}, map[jobKey]Job{}}, func(v memoryState) memoryState {
		v.authorities = maps.Clone(v.authorities)
		v.profiles = maps.Clone(v.profiles)
		v.jobs = maps.Clone(v.jobs)
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
func cloneAuthority(v Authority) Authority {
	v.Certificate = slices.Clone(v.Certificate)
	v.PrivateKey = slices.Clone(v.PrivateKey)
	return v
}
func cloneProfile(v Profile) Profile {
	v.Certificate = slices.Clone(v.Certificate)
	v.PrivateKey = slices.Clone(v.PrivateKey)
	v.Tags = maps.Clone(v.Tags)
	return v
}
func cloneJob(v Job) Job { v.CertificateHashes = slices.Clone(v.CertificateHashes); return v }
func (r memoryReader) Authority(sc Scope) (Authority, error) {
	if e := r.t.Check(false); e != nil {
		return Authority{}, e
	}
	v, ok := r.s.authorities[sc]
	if !ok {
		return v, ErrNotFound
	}
	return cloneAuthority(v), nil
}
func (r memoryReader) Authorities() ([]Authority, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Authority, 0, len(r.s.authorities))
	for _, v := range r.s.authorities {
		out = append(out, cloneAuthority(v))
	}
	return out, nil
}
func (r memoryReader) Profile(sc Scope, name, version string) (Profile, error) {
	if e := r.t.Check(false); e != nil {
		return Profile{}, e
	}
	if version != "" {
		v, ok := r.s.profiles[profileKey{sc, name, version}]
		if !ok {
			return v, ErrNotFound
		}
		return cloneProfile(v), nil
	}
	for k, v := range r.s.profiles {
		if k.Scope == sc && k.Name == name && v.Current {
			return cloneProfile(v), nil
		}
	}
	return Profile{}, ErrNotFound
}
func (r memoryReader) Profiles(sc Scope) ([]Profile, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Profile{}
	for k, v := range r.s.profiles {
		if k.Scope == sc {
			out = append(out, cloneProfile(v))
		}
	}
	slices.SortFunc(out, func(a, b Profile) int { return cmp.Compare(a.VersionARN, b.VersionARN) })
	return out, nil
}
func (r memoryReader) Job(sc Scope, id string) (Job, error) {
	if e := r.t.Check(false); e != nil {
		return Job{}, e
	}
	v, ok := r.s.jobs[jobKey{sc, id}]
	if !ok {
		return v, ErrNotFound
	}
	return cloneJob(v), nil
}
func (r memoryReader) Jobs(sc Scope) ([]Job, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := []Job{}
	for k, v := range r.s.jobs {
		if k.Scope == sc {
			out = append(out, cloneJob(v))
		}
	}
	slices.SortFunc(out, func(a, b Job) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutAuthority(v Authority) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.authorities[v.Scope] = cloneAuthority(v)
	return nil
}
func (w memoryWriter) PutProfile(v Profile) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.profiles[profileKey{v.Scope, v.Name, v.Version}] = cloneProfile(v)
	return nil
}
func (w memoryWriter) PutJob(v Job) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.jobs[jobKey{v.Scope, v.ID}] = cloneJob(v)
	return nil
}
