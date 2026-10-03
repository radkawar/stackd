package identitystore

import (
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	stores      map[string]Store
	users       map[Key]User
	groups      map[Key]Group
	memberships map[Key]Membership
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[string]Store{}, map[Key]User{}, map[Key]Group{}, map[Key]Membership{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.stores), maps.Clone(v.users), maps.Clone(v.groups), maps.Clone(v.memberships)}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryReader{v, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{v, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(v *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{v, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneUser(v User) User                     { v.Emails = slices.Clone(v.Emails); return v }
func (r memoryReader) Store(id string) (Store, error) {
	if e := r.tx.Check(false); e != nil {
		return Store{}, e
	}
	v, ok := r.s.stores[id]
	if !ok {
		return Store{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) User(k Key) (User, error) {
	if e := r.tx.Check(false); e != nil {
		return User{}, e
	}
	v, ok := r.s.users[k]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(v), nil
}
func (r memoryReader) UserByName(store, name string) (User, error) {
	if e := r.tx.Check(false); e != nil {
		return User{}, e
	}
	for k, v := range r.s.users {
		if k.StoreID == store && v.UserName == name {
			return cloneUser(v), nil
		}
	}
	return User{}, ErrNotFound
}
func (r memoryReader) Users(store string) ([]User, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []User{}
	for k, v := range r.s.users {
		if k.StoreID == store {
			out = append(out, cloneUser(v))
		}
	}
	slices.SortFunc(out, func(a, b User) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Group(k Key) (Group, error) {
	if e := r.tx.Check(false); e != nil {
		return Group{}, e
	}
	v, ok := r.s.groups[k]
	if !ok {
		return Group{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) GroupByName(store, name string) (Group, error) {
	if e := r.tx.Check(false); e != nil {
		return Group{}, e
	}
	for k, v := range r.s.groups {
		if k.StoreID == store && v.DisplayName == name {
			return v, nil
		}
	}
	return Group{}, ErrNotFound
}
func (r memoryReader) Groups(store string) ([]Group, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Group{}
	for k, v := range r.s.groups {
		if k.StoreID == store {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Membership(k Key) (Membership, error) {
	if e := r.tx.Check(false); e != nil {
		return Membership{}, e
	}
	v, ok := r.s.memberships[k]
	if !ok {
		return Membership{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) MembershipFor(store, user, group string) (Membership, error) {
	if e := r.tx.Check(false); e != nil {
		return Membership{}, e
	}
	for k, v := range r.s.memberships {
		if k.StoreID == store && v.UserID == user && v.GroupID == group {
			return v, nil
		}
	}
	return Membership{}, ErrNotFound
}
func (r memoryReader) Memberships(store, user, group string) ([]Membership, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Membership{}
	for k, v := range r.s.memberships {
		if k.StoreID == store && (user == "" || v.UserID == user) && (group == "" || v.GroupID == group) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Membership) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutStore(v Store) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.stores[v.ID] = v
	return nil
}
func (w memoryWriter) PutUser(v User) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.users[Key{v.StoreID, v.ID}] = cloneUser(v)
	return nil
}
func (w memoryWriter) PutGroup(v Group) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.groups[Key{v.StoreID, v.ID}] = v
	return nil
}
func (w memoryWriter) PutMembership(v Membership) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.memberships[Key{v.StoreID, v.ID}] = v
	return nil
}
func (w memoryWriter) DeleteMembership(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.memberships, k)
	return nil
}
func (w memoryWriter) DeleteUser(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.users, k)
	for mk, m := range w.s.memberships {
		if mk.StoreID == k.StoreID && m.UserID == k.ID {
			delete(w.s.memberships, mk)
		}
	}
	return nil
}
func (w memoryWriter) DeleteGroup(k Key) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.groups, k)
	for mk, m := range w.s.memberships {
		if mk.StoreID == k.StoreID && m.GroupID == k.ID {
			delete(w.s.memberships, mk)
		}
	}
	return nil
}

var _ Repository = (*MemoryRepository)(nil)

func (w memoryWriter) DeleteStore(id string) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.stores, id)
	for k := range w.s.users {
		if k.StoreID == id {
			delete(w.s.users, k)
		}
	}
	for k := range w.s.groups {
		if k.StoreID == id {
			delete(w.s.groups, k)
		}
	}
	for k := range w.s.memberships {
		if k.StoreID == id {
			delete(w.s.memberships, k)
		}
	}
	return nil
}
