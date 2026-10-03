package secretsmanager

import (
	"cmp"
	"context"
	"maps"
	"slices"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/storage/memory"
)

type memoryState struct {
	secrets   map[SecretKey]SecretRecord
	versions  map[VersionKey]VersionRecord
	values    map[VersionKey][]SealedValue
	replicas  map[ReplicaKey]ReplicaRecord
	rotations map[SecretKey]RotationRecord
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{secrets: map[SecretKey]SecretRecord{}, versions: map[VersionKey]VersionRecord{}, values: map[VersionKey][]SealedValue{}, replicas: map[ReplicaKey]ReplicaRecord{}, rotations: map[SecretKey]RotationRecord{}}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.secrets = maps.Clone(s.secrets)
		s.versions = maps.Clone(s.versions)
		s.values = maps.Clone(s.values)
		s.replicas = maps.Clone(s.replicas)
		s.rotations = maps.Clone(s.rotations)
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

func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	return new(*p)
}

func cloneSecret(v SecretRecord) SecretRecord {
	v.Description = clonePointer(v.Description)
	v.LastAccessed = clonePointer(v.LastAccessed)
	v.Deleted, v.DeleteAfter = clonePointer(v.Deleted), clonePointer(v.DeleteAfter)
	v.LastRotated, v.NextRotation = clonePointer(v.LastRotated), clonePointer(v.NextRotation)
	v.RotationEnabled = clonePointer(v.RotationEnabled)
	v.RotationDue = clonePointer(v.RotationDue)
	v.Tags = maps.Clone(v.Tags)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	if v.RotationRules != nil {
		v.RotationRules = new(api.CloneRotationRulesType(*v.RotationRules))
	}
	return v
}

func cloneVersion(v VersionRecord) VersionRecord {
	v.Stages = slices.Clone(v.Stages)
	v.LastAccessed = clonePointer(v.LastAccessed)
	return v
}

func cloneValues(values []SealedValue) []SealedValue {
	values = slices.Clone(values)
	for i := range values {
		values[i].WrappedKey = slices.Clone(values[i].WrappedKey)
		values[i].Payload = slices.Clone(values[i].Payload)
	}
	return values
}

func (r memoryReader) EncryptedVersion(key VersionKey) ([]SealedValue, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	values, ok := r.s.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneValues(values), nil
}

func (r memoryReader) VersionKeyIDs(key VersionKey) ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	values, ok := r.s.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	keys := make([]string, len(values))
	for i := range values {
		keys[i] = values[i].KeyID
	}
	return keys, nil
}

func (w memoryWriter) PutEncryptedVersion(key VersionKey, values []SealedValue) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.values[key] = cloneValues(values)
	return nil
}

func (r memoryReader) Secret(key SecretKey) (SecretRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SecretRecord{}, err
	}
	value, ok := r.s.secrets[key]
	if !ok {
		return SecretRecord{}, ErrNotFound
	}
	return cloneSecret(value), nil
}

func (r memoryReader) Secrets(scope Scope) ([]SecretRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]SecretRecord, 0)
	for key, value := range r.s.secrets {
		if key.Scope == scope {
			rows = append(rows, cloneSecret(value))
		}
	}
	slices.SortFunc(rows, func(a, b SecretRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) Version(key VersionKey) (VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VersionRecord{}, err
	}
	value, ok := r.s.versions[key]
	if !ok {
		return VersionRecord{}, ErrNotFound
	}
	return cloneVersion(value), nil
}

func (r memoryReader) Versions(key SecretKey) ([]VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]VersionRecord, 0)
	for k, value := range r.s.versions {
		if k.Secret == key {
			rows = append(rows, cloneVersion(value))
		}
	}
	slices.SortFunc(rows, func(a, b VersionRecord) int {
		if order := a.Created.Compare(b.Created); order != 0 {
			return order
		}
		return cmp.Compare(a.Key.ID, b.Key.ID)
	})
	return rows, nil
}

func (r memoryReader) NextDeletion() (SecretRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SecretRecord{}, err
	}
	var next SecretRecord
	for _, value := range r.s.secrets {
		if value.DeleteAfter != nil && (next.DeleteAfter == nil || value.DeleteAfter.Before(*next.DeleteAfter) || value.DeleteAfter.Equal(*next.DeleteAfter) && value.ARN < next.ARN) {
			next = value
		}
	}
	if next.DeleteAfter == nil {
		return SecretRecord{}, ErrNotFound
	}
	return cloneSecret(next), nil
}

func (w memoryWriter) PutSecret(value SecretRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.secrets[value.Key] = cloneSecret(value)
	return nil
}

func (w memoryWriter) DeleteSecret(key SecretKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.secrets, key)
	delete(w.s.rotations, key)
	for replica := range w.s.replicas {
		if replica.Primary == key {
			delete(w.s.replicas, replica)
		}
	}
	for version := range w.s.versions {
		if version.Secret == key {
			delete(w.s.versions, version)
			delete(w.s.values, version)
		}
	}
	return nil
}

func (w memoryWriter) PutVersion(value VersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.versions[value.Key] = cloneVersion(value)
	return nil
}

func (w memoryWriter) DeleteVersion(key VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.versions, key)
	delete(w.s.values, key)
	return nil
}
