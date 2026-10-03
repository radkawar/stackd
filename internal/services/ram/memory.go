package ram

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
)

type receiptKey struct {
	Scope
	Operation, Token string
}
type memoryState struct {
	shares       map[string]Share
	invitations  map[string]Invitation
	permissions  map[string]Permission
	receipts     map[receiptKey]Receipt
	replacements map[string]Replacement
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{shares: map[string]Share{}, invitations: map[string]Invitation{}, permissions: map[string]Permission{}, receipts: map[receiptKey]Receipt{}, replacements: map[string]Replacement{}}, func(s memoryState) memoryState {
		s.shares = maps.Clone(s.shares)
		s.invitations = maps.Clone(s.invitations)
		s.permissions = maps.Clone(s.permissions)
		s.receipts = maps.Clone(s.receipts)
		s.replacements = maps.Clone(s.replacements)
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
func cloneShare(v Share) Share {
	v.Tags = maps.Clone(v.Tags)
	v.Resources = slices.Clone(v.Resources)
	v.Principals = slices.Clone(v.Principals)
	v.Permissions = slices.Clone(v.Permissions)
	return v
}
func clonePermission(v Permission) Permission {
	v.Tags = maps.Clone(v.Tags)
	v.Versions = slices.Clone(v.Versions)
	for i := range v.Versions {
		v.Versions[i].Actions = slices.Clone(v.Versions[i].Actions)
	}
	return v
}
func (r memoryReader) Share(key string) (Share, error) {
	if e := r.t.Check(false); e != nil {
		return Share{}, e
	}
	v, ok := r.s.shares[key]
	if !ok {
		return Share{}, ErrNotFound
	}
	return cloneShare(v), nil
}
func (r memoryReader) Shares() ([]Share, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Share, 0, len(r.s.shares))
	for _, v := range r.s.shares {
		out = append(out, cloneShare(v))
	}
	slices.SortFunc(out, func(a, b Share) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutShare(v Share) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.shares[v.ARN] = cloneShare(v)
	return nil
}
func (r memoryReader) Invitation(key string) (Invitation, error) {
	if e := r.t.Check(false); e != nil {
		return Invitation{}, e
	}
	v, ok := r.s.invitations[key]
	if !ok {
		return Invitation{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Invitations() ([]Invitation, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Invitation, 0, len(r.s.invitations))
	for _, v := range r.s.invitations {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Invitation) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutInvitation(v Invitation) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.invitations[v.ARN] = v
	return nil
}
func (r memoryReader) Permission(key string) (Permission, error) {
	if e := r.t.Check(false); e != nil {
		return Permission{}, e
	}
	v, ok := r.s.permissions[key]
	if !ok {
		return Permission{}, ErrNotFound
	}
	return clonePermission(v), nil
}
func (r memoryReader) Permissions() ([]Permission, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Permission, 0, len(r.s.permissions))
	for _, v := range r.s.permissions {
		out = append(out, clonePermission(v))
	}
	slices.SortFunc(out, func(a, b Permission) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (w memoryWriter) PutPermission(v Permission) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.permissions[v.ARN] = clonePermission(v)
	return nil
}
func (r memoryReader) Replacements() ([]Replacement, error) {
	if e := r.t.Check(false); e != nil {
		return nil, e
	}
	out := make([]Replacement, 0, len(r.s.replacements))
	for _, v := range r.s.replacements {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Replacement) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutReplacement(v Replacement) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.replacements[v.ID] = v
	return nil
}
func (r memoryReader) Receipt(s Scope, op, t string) (Receipt, error) {
	if e := r.t.Check(false); e != nil {
		return Receipt{}, e
	}
	v, ok := r.s.receipts[receiptKey{s, op, t}]
	if !ok {
		return Receipt{}, ErrNotFound
	}
	return v, nil
}
func (w memoryWriter) PutReceipt(v Receipt) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	w.s.receipts[receiptKey{v.Scope, v.Operation, v.Token}] = v
	return nil
}
func (w memoryWriter) DeletePermission(arn string) error {
	if e := w.t.Check(true); e != nil {
		return e
	}
	delete(w.s.permissions, arn)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
