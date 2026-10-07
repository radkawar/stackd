package identitycenter

import (
	"context"
	"maps"
	"slices"
	"stackd/storage/memory"
	"strings"
)

type memoryState struct {
	instances      map[string]Instance
	permissions    map[string]PermissionSet
	assignments    map[Assignment]Assignment
	provisions     map[string]Provisioning
	operations     map[string]Operation
	clients        map[string]Client
	devices        map[string]Device
	sessions       map[string]Session
	authorizations map[string]Authorization
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(d, memoryState{map[string]Instance{}, map[string]PermissionSet{}, map[Assignment]Assignment{}, map[string]Provisioning{}, map[string]Operation{}, map[string]Client{}, map[string]Device{}, map[string]Session{}, map[string]Authorization{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.instances), maps.Clone(v.permissions), maps.Clone(v.assignments), maps.Clone(v.provisions), maps.Clone(v.operations), maps.Clone(v.clients), maps.Clone(v.devices), maps.Clone(v.sessions), maps.Clone(v.authorizations)}
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
func cloneInstance(v Instance) Instance         { v.Tags = maps.Clone(v.Tags); return v }
func clonePermission(v PermissionSet) PermissionSet {
	v.Tags = maps.Clone(v.Tags)
	v.ManagedPolicies = slices.Clone(v.ManagedPolicies)
	v.CustomerManagedPolicies = slices.Clone(v.CustomerManagedPolicies)
	return v
}
func cloneClient(v Client) Client {
	v.Scopes = slices.Clone(v.Scopes)
	v.GrantTypes = slices.Clone(v.GrantTypes)
	v.RedirectURIs = slices.Clone(v.RedirectURIs)
	return v
}
func memoryGet[K comparable, V any](r memoryReader, m map[K]V, k K) (V, error) {
	var zero V
	if e := r.tx.Check(false); e != nil {
		return zero, e
	}
	v, ok := m[k]
	if !ok {
		return zero, ErrNotFound
	}
	return v, nil
}
func memoryPut[K comparable, V any](w memoryWriter, m map[K]V, k K, v V) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	m[k] = v
	return nil
}
func memoryDelete[K comparable, V any](w memoryWriter, m map[K]V, k K) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(m, k)
	return nil
}
func (r memoryReader) Instance(k string) (Instance, error) {
	v, e := memoryGet(r, r.v.instances, k)
	return cloneInstance(v), e
}
func (r memoryReader) Instances(scope Scope) ([]Instance, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Instance{}
	for _, v := range r.v.instances {
		if v.Scope == scope {
			out = append(out, cloneInstance(v))
		}
	}
	slices.SortFunc(out, func(a, b Instance) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) PermissionSet(k string) (PermissionSet, error) {
	v, e := memoryGet(r, r.v.permissions, k)
	return clonePermission(v), e
}
func (r memoryReader) PermissionSets(instance string) ([]PermissionSet, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []PermissionSet{}
	for _, v := range r.v.permissions {
		if v.InstanceARN == instance {
			out = append(out, clonePermission(v))
		}
	}
	slices.SortFunc(out, func(a, b PermissionSet) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) Assignments(instance string) ([]Assignment, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Assignment{}
	for _, v := range r.v.assignments {
		if v.InstanceARN == instance {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Assignment) int { return strings.Compare(assignmentKey(a), assignmentKey(b)) })
	return out, nil
}
func assignmentKey(v Assignment) string {
	return v.PermissionSetARN + "/" + v.AccountID + "/" + v.PrincipalType + "/" + v.PrincipalID
}
func provisioningKey(v Provisioning) string { return v.PermissionSetARN + "/" + v.AccountID }
func (r memoryReader) Provisionings(instance string) ([]Provisioning, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Provisioning{}
	for _, v := range r.v.provisions {
		if v.InstanceARN == instance {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Provisioning) int { return strings.Compare(provisioningKey(a), provisioningKey(b)) })
	return out, nil
}
func (r memoryReader) Operation(k string) (Operation, error) { return memoryGet(r, r.v.operations, k) }
func (r memoryReader) Operations(instance string) ([]Operation, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Operation{}
	for _, v := range r.v.operations {
		if v.InstanceARN == instance {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Operation) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) Client(k string) (Client, error) {
	v, e := memoryGet(r, r.v.clients, k)
	return cloneClient(v), e
}
func (r memoryReader) Device(k string) (Device, error) { return memoryGet(r, r.v.devices, k) }
func (r memoryReader) DeviceByUserCode(code string) (Device, error) {
	if e := r.tx.Check(false); e != nil {
		return Device{}, e
	}
	for _, v := range r.v.devices {
		if v.UserCode == code {
			return v, nil
		}
	}
	return Device{}, ErrNotFound
}
func (r memoryReader) SessionByAccess(hash string) (Session, error) {
	if e := r.tx.Check(false); e != nil {
		return Session{}, e
	}
	for _, v := range r.v.sessions {
		if v.AccessHash == hash {
			return v, nil
		}
	}
	return Session{}, ErrNotFound
}
func (r memoryReader) SessionByRefresh(hash string) (Session, error) {
	if e := r.tx.Check(false); e != nil {
		return Session{}, e
	}
	for _, v := range r.v.sessions {
		if v.RefreshHash == hash {
			return v, nil
		}
	}
	return Session{}, ErrNotFound
}
func (w memoryWriter) PutInstance(v Instance) error {
	return memoryPut(w, w.v.instances, v.ARN, cloneInstance(v))
}
func (w memoryWriter) DeleteInstance(k string) error { return memoryDelete(w, w.v.instances, k) }
func (w memoryWriter) PutPermissionSet(v PermissionSet) error {
	return memoryPut(w, w.v.permissions, v.ARN, clonePermission(v))
}
func (w memoryWriter) DeletePermissionSet(k string) error { return memoryDelete(w, w.v.permissions, k) }
func (w memoryWriter) PutAssignment(v Assignment) error {
	key := v
	key.CloudFormationOwner = ""
	return memoryPut(w, w.v.assignments, key, v)
}
func (w memoryWriter) DeleteAssignment(v Assignment) error {
	v.CloudFormationOwner = ""
	return memoryDelete(w, w.v.assignments, v)
}
func (w memoryWriter) PutProvisioning(v Provisioning) error {
	return memoryPut(w, w.v.provisions, provisioningKey(v), v)
}
func (w memoryWriter) DeleteProvisioning(v Provisioning) error {
	return memoryDelete(w, w.v.provisions, provisioningKey(v))
}
func (w memoryWriter) PutOperation(v Operation) error { return memoryPut(w, w.v.operations, v.ID, v) }
func (w memoryWriter) PutClient(v Client) error {
	return memoryPut(w, w.v.clients, v.ID, cloneClient(v))
}
func (w memoryWriter) PutDevice(v Device) error   { return memoryPut(w, w.v.devices, v.CodeHash, v) }
func (w memoryWriter) PutSession(v Session) error { return memoryPut(w, w.v.sessions, v.ID, v) }
func (r memoryReader) Sessions(family string) ([]Session, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []Session{}
	for _, v := range r.v.sessions {
		if v.FamilyID == family {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Session) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (r memoryReader) Authorization(id string) (Authorization, error) {
	return memoryGet(r, r.v.authorizations, id)
}
func (r memoryReader) AuthorizationByCode(hash string) (Authorization, error) {
	if e := r.tx.Check(false); e != nil {
		return Authorization{}, e
	}
	for _, v := range r.v.authorizations {
		if v.CodeHash == hash {
			return v, nil
		}
	}
	return Authorization{}, ErrNotFound
}
func (w memoryWriter) PutAuthorization(v Authorization) error {
	return memoryPut(w, w.v.authorizations, v.ID, v)
}
