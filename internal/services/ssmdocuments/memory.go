package ssmdocuments

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type memoryState struct {
	documents map[Key]Record
	versions  map[VersionKey]Version
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, memoryState{map[Key]Record{}, map[VersionKey]Version{}}, func(s memoryState) memoryState {
		s.documents = maps.Clone(s.documents)
		s.versions = maps.Clone(s.versions)
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
func cloneRecord(v Record) Record {
	v.Tags = maps.Clone(v.Tags)
	v.Shares = maps.Clone(v.Shares)
	return v
}
func (r memoryReader) Document(k Key) (Record, error) {
	if err := r.tx.Check(false); err != nil {
		return Record{}, err
	}
	v, ok := r.s.documents[k]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(v), nil
}
func (r memoryReader) Documents(sc Scope) ([]Record, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Record{}
	for k, v := range r.s.documents {
		if k.Scope == sc {
			out = append(out, cloneRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b Record) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) SharedDocuments(sc Scope) ([]Record, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Record{}
	for k, v := range r.s.documents {
		if k.Partition == sc.Partition && k.Region == sc.Region && k.AccountID != sc.AccountID && sharedSelector(v, sc.AccountID) != "" {
			out = append(out, cloneRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b Record) int { return cmp.Compare(documentARN(a.Key), documentARN(b.Key)) })
	return out, nil
}
func (r memoryReader) Version(k VersionKey) (Version, error) {
	if err := r.tx.Check(false); err != nil {
		return Version{}, err
	}
	v, ok := r.s.versions[k]
	if !ok {
		return Version{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Versions(k Key) ([]Version, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []Version{}
	for vk, v := range r.s.versions {
		if vk.Document == k {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Version) int { return cmp.Compare(a.Key.Version, b.Key.Version) })
	return out, nil
}
func (w memoryWriter) PutDocument(v Record) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.documents[v.Key] = cloneRecord(v)
	return nil
}
func (w memoryWriter) DeleteDocument(k Key) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.documents, k)
	for vk := range w.s.versions {
		if vk.Document == k {
			delete(w.s.versions, vk)
		}
	}
	return nil
}
func (w memoryWriter) InsertVersion(v Version) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.documents[v.Key.Document]; !ok {
		return ErrNotFound
	}
	if _, ok := w.s.versions[v.Key]; ok {
		return fmt.Errorf("document version already exists")
	}
	for k, old := range w.s.versions {
		if k.Document == v.Key.Document && v.VersionName != "" && old.VersionName == v.VersionName {
			return fmt.Errorf("document version name already exists")
		}
	}
	w.s.versions[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteVersion(k VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.versions, k)
	return nil
}

func (r memoryReader) NextActivation() (Activation, error) {
	if err := r.tx.Check(false); err != nil {
		return Activation{}, err
	}
	var first Version
	found := false
	for _, v := range r.s.versions {
		if !pendingStatus(v.Status) {
			continue
		}
		a, b := v.Key.Document, first.Key.Document
		order := cmp.Or(v.ReadyAt.Compare(first.ReadyAt), cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name), cmp.Compare(v.Key.Version, first.Key.Version))
		if !found || order < 0 {
			first, found = v, true
		}
	}
	if !found {
		return Activation{}, ErrNotFound
	}
	return Activation{Key: first.Key, DocumentID: r.s.documents[first.Key.Document].DocumentID, Due: first.ReadyAt}, nil
}

func (w memoryWriter) ActivateVersion(k VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.s.versions[k]
	if !ok {
		return ErrNotFound
	}
	v.Status = "Active"
	w.s.versions[k] = v
	return nil
}
