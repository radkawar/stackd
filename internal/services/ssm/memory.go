package ssm

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	"stackd/internal/awsctx"
	"stackd/storage/memory"
)

type memorySettingKey struct {
	Scope
	ID string
}
type memoryState struct {
	parameters map[ParameterKey]ParameterRecord
	versions   map[VersionKey]VersionRecord
	settings   map[memorySettingKey]SettingRecord
	jobs       map[VersionKey]ValidationJob
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{parameters: map[ParameterKey]ParameterRecord{}, versions: map[VersionKey]VersionRecord{}, settings: map[memorySettingKey]SettingRecord{}, jobs: map[VersionKey]ValidationJob{}}
	return &MemoryRepository{store: memory.New(domain, initial, func(s memoryState) memoryState {
		s.parameters = maps.Clone(s.parameters)
		s.versions = maps.Clone(s.versions)
		s.settings = maps.Clone(s.settings)
		s.jobs = maps.Clone(s.jobs)
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

func cloneStoredPolicies(v []ParameterPolicy) []ParameterPolicy {
	v = slices.Clone(v)
	for i := range v {
		v[i].Attributes = maps.Clone(v[i].Attributes)
	}
	return v
}
func cloneStoredParameter(v ParameterRecord) ParameterRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Policies = cloneStoredPolicies(v.Policies)
	v.ResourcePolicies = slices.Clone(v.ResourcePolicies)
	for i := range v.ResourcePolicies {
		v.ResourcePolicies[i].Policy.PrincipalIDs = maps.Clone(v.ResourcePolicies[i].Policy.PrincipalIDs)
	}
	return v
}
func cloneStoredVersion(v VersionRecord) VersionRecord {
	v.Value = slices.Clone(v.Value)
	v.WrappedKey = slices.Clone(v.WrappedKey)
	v.Labels = slices.Clone(v.Labels)
	v.Policies = cloneStoredPolicies(v.Policies)
	return v
}
func compareStoredKeys(a, b ParameterKey) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name))
}
func (r memoryReader) Parameter(key ParameterKey) (ParameterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ParameterRecord{}, err
	}
	v, ok := r.s.parameters[key]
	if !ok {
		return ParameterRecord{}, ErrNotFound
	}
	return cloneStoredParameter(v), nil
}
func (r memoryReader) Parameters(scope Scope) ([]ParameterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]ParameterRecord, 0)
	for k, v := range r.s.parameters {
		if k.Scope == scope {
			out = append(out, cloneStoredParameter(v))
		}
	}
	slices.SortFunc(out, func(a, b ParameterRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Version(key VersionKey) (VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return VersionRecord{}, err
	}
	v, ok := r.s.versions[key]
	if !ok {
		return VersionRecord{}, ErrNotFound
	}
	return cloneStoredVersion(v), nil
}
func (r memoryReader) Versions(key ParameterKey) ([]VersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]VersionRecord, 0)
	for k, v := range r.s.versions {
		if k.Parameter == key {
			out = append(out, cloneStoredVersion(v))
		}
	}
	slices.SortFunc(out, func(a, b VersionRecord) int { return cmp.Compare(a.Key.Version, b.Key.Version) })
	return out, nil
}
func (r memoryReader) Settings(scope Scope) ([]SettingRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]SettingRecord, 0)
	for k, v := range r.s.settings {
		if k.Scope == scope {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b SettingRecord) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) NextPolicy() (ParameterRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ParameterRecord{}, err
	}
	var next ParameterRecord
	var due time.Time
	for _, v := range r.s.parameters {
		for _, p := range v.Policies {
			if p.Fired || p.Due.IsZero() {
				continue
			}
			if due.IsZero() || p.Due.Before(due) || p.Due.Equal(due) && compareStoredKeys(v.Key, next.Key) < 0 {
				next, due = v, p.Due
			}
		}
	}
	if due.IsZero() {
		return ParameterRecord{}, ErrNotFound
	}
	return cloneStoredParameter(next), nil
}
func (r memoryReader) ValidationJob(key VersionKey) (ValidationJob, error) {
	if err := r.tx.Check(false); err != nil {
		return ValidationJob{}, err
	}
	v, ok := r.s.jobs[key]
	if !ok {
		return ValidationJob{}, ErrNotFound
	}
	v.Caller = awsctx.Clone(v.Caller)
	return v, nil
}
func (r memoryReader) NextValidationJob() (ValidationJob, error) {
	if err := r.tx.Check(false); err != nil {
		return ValidationJob{}, err
	}
	var next ValidationJob
	found := false
	for _, v := range r.s.jobs {
		if !found || cmp.Or(v.Due.Compare(next.Due), compareStoredKeys(v.Key.Parameter, next.Key.Parameter), cmp.Compare(v.Key.Version, next.Key.Version)) < 0 {
			next, found = v, true
		}
	}
	if !found {
		return ValidationJob{}, ErrNotFound
	}
	next.Caller = awsctx.Clone(next.Caller)
	return next, nil
}
func (w memoryWriter) PutParameter(v ParameterRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if current, exists := w.s.parameters[v.Key]; exists {
		v.Incarnation, v.CloudFormationOwner = current.Incarnation, current.CloudFormationOwner
	}
	w.s.parameters[v.Key] = cloneStoredParameter(v)
	return nil
}
func (w memoryWriter) DeleteParameter(key ParameterKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.parameters, key)
	for k := range w.s.versions {
		if k.Parameter == key {
			delete(w.s.versions, k)
		}
	}
	for k := range w.s.jobs {
		if k.Parameter == key {
			delete(w.s.jobs, k)
		}
	}
	return nil
}
func (w memoryWriter) PutVersion(v VersionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.versions[v.Key] = cloneStoredVersion(v)
	return nil
}
func (w memoryWriter) DeleteVersion(key VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.versions, key)
	delete(w.s.jobs, key)
	return nil
}
func (w memoryWriter) PutSetting(v SettingRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.settings[memorySettingKey{v.Scope, v.ID}] = v
	return nil
}
func (w memoryWriter) PutValidationJob(v ValidationJob) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Caller = awsctx.Clone(v.Caller)
	w.s.jobs[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteValidationJob(key VersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.jobs, key)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
