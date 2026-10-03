package sesv2

import (
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	identities     map[ResourceKey]Identity
	templates      map[ResourceKey]Template
	configurations map[ResourceKey]ConfigurationSet
	accounts       map[Scope]Account
	messages       map[ResourceKey]Message
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[ResourceKey]Identity{}, map[ResourceKey]Template{}, map[ResourceKey]ConfigurationSet{}, map[Scope]Account{}, map[ResourceKey]Message{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.identities), maps.Clone(v.templates), maps.Clone(v.configurations), maps.Clone(v.accounts), maps.Clone(v.messages)}
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
	v  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneIdentity(v Identity) Identity {
	v.Tags = maps.Clone(v.Tags)
	v.Policies = maps.Clone(v.Policies)
	for name, bound := range v.Policies {
		bound.PrincipalIDs = maps.Clone(bound.PrincipalIDs)
		v.Policies[name] = bound
	}
	return v
}
func cloneConfiguration(v ConfigurationSet) ConfigurationSet { v.Tags = maps.Clone(v.Tags); return v }
func cloneMessage(v Message) Message {
	v.To = slices.Clone(v.To)
	v.CC = slices.Clone(v.CC)
	v.BCC = slices.Clone(v.BCC)
	v.ReplyTo = slices.Clone(v.ReplyTo)
	v.Tags = maps.Clone(v.Tags)
	v.MIME = slices.Clone(v.MIME)
	return v
}
func (r memoryReader) Identity(k ResourceKey) (Identity, error) {
	if e := r.tx.Check(false); e != nil {
		return Identity{}, e
	}
	v, ok := r.v.identities[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneIdentity(v), nil
}
func (r memoryReader) Identities(k Scope) ([]Identity, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Identity{}
	for key, v := range r.v.identities {
		if key.Scope == k {
			out = append(out, cloneIdentity(v))
		}
	}
	slices.SortFunc(out, func(a, b Identity) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) IdentityByToken(token string) (Identity, error) {
	if e := r.tx.Check(false); e != nil {
		return Identity{}, e
	}
	for _, v := range r.v.identities {
		if v.VerificationToken == token && token != "" {
			return cloneIdentity(v), nil
		}
	}
	return Identity{}, ErrNotFound
}
func (r memoryReader) Template(k ResourceKey) (Template, error) {
	if e := r.tx.Check(false); e != nil {
		return Template{}, e
	}
	v, ok := r.v.templates[k]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) Templates(k Scope) ([]Template, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Template{}
	for key, v := range r.v.templates {
		if key.Scope == k {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Template) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) ConfigurationSet(k ResourceKey) (ConfigurationSet, error) {
	if e := r.tx.Check(false); e != nil {
		return ConfigurationSet{}, e
	}
	v, ok := r.v.configurations[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneConfiguration(v), nil
}
func (r memoryReader) ConfigurationSets(k Scope) ([]ConfigurationSet, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ConfigurationSet{}
	for key, v := range r.v.configurations {
		if key.Scope == k {
			out = append(out, cloneConfiguration(v))
		}
	}
	slices.SortFunc(out, func(a, b ConfigurationSet) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Account(k Scope) (Account, error) {
	if e := r.tx.Check(false); e != nil {
		return Account{}, e
	}
	v, ok := r.v.accounts[k]
	if !ok {
		return Account{Scope: k, SendingEnabled: true}, nil
	}
	return v, nil
}
func (r memoryReader) Message(k ResourceKey) (Message, error) {
	if e := r.tx.Check(false); e != nil {
		return Message{}, e
	}
	v, ok := r.v.messages[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneMessage(v), nil
}
func (r memoryReader) Messages(k Scope) ([]Message, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Message{}
	for key, v := range r.v.messages {
		if key.Scope == k {
			out = append(out, cloneMessage(v))
		}
	}
	slices.SortFunc(out, func(a, b Message) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) NextCapture() (Message, bool, error) {
	if e := r.tx.Check(false); e != nil {
		return Message{}, false, e
	}
	var out Message
	found := false
	for _, v := range r.v.messages {
		if v.CapturePending && (!found || v.Due.Before(out.Due) || v.Due.Equal(out.Due) && v.Key.ARN("message") < out.Key.ARN("message")) {
			out = v
			found = true
		}
	}
	return cloneMessage(out), found, nil
}
func (w memoryWriter) PutIdentity(v Identity) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.v.identities[v.Key] = cloneIdentity(v)
	return nil
}
func (w memoryWriter) DeleteIdentity(k ResourceKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.v.identities, k)
	return nil
}
func (w memoryWriter) PutTemplate(v Template) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.v.templates[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteTemplate(k ResourceKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.v.templates, k)
	return nil
}
func (w memoryWriter) PutConfigurationSet(v ConfigurationSet) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.v.configurations[v.Key] = cloneConfiguration(v)
	return nil
}
func (w memoryWriter) DeleteConfigurationSet(k ResourceKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.v.configurations, k)
	return nil
}
func (w memoryWriter) PutAccount(v Account) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.v.accounts[v.Scope] = v
	return nil
}
func (w memoryWriter) PutMessage(v Message) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.v.messages[v.Key] = cloneMessage(v)
	return nil
}
