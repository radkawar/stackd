package codebuild

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/codebuild"
	"stackd/storage/memory"
)

type memoryState struct {
	projects    map[ProjectKey]ProjectRecord
	builds      map[BuildKey]BuildRecord
	fleets      map[FleetKey]FleetRecord
	credentials map[CredentialKey]CredentialRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	return &MemoryRepository{memory.New(domain, memoryState{map[ProjectKey]ProjectRecord{}, map[BuildKey]BuildRecord{}, map[FleetKey]FleetRecord{}, map[CredentialKey]CredentialRecord{}}, func(v memoryState) memoryState {
		return memoryState{maps.Clone(v.projects), maps.Clone(v.builds), maps.Clone(v.fleets), maps.Clone(v.credentials)}
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

func (r memoryReader) Context() context.Context  { return r.tx.Context() }
func cloneProject(v ProjectRecord) ProjectRecord { v.Data = api.CloneProject(v.Data); return v }
func cloneBuild(v BuildRecord) BuildRecord {
	v.Data = api.CloneBuild(v.Data)
	v.Artifacts = api.CloneProjectArtifacts(v.Artifacts)
	v.SecondaryArtifacts = api.CloneProject(api.Project{SecondaryArtifacts: v.SecondaryArtifacts}).SecondaryArtifacts
	v.Logs = api.CloneLogsConfig(v.Logs)
	v.PipelineInputs = slices.Clone(v.PipelineInputs)
	v.PipelineOutputs = slices.Clone(v.PipelineOutputs)
	return v
}
func cloneFleet(v FleetRecord) FleetRecord { v.Data = api.CloneFleet(v.Data); return v }
func cloneCredential(v CredentialRecord) CredentialRecord {
	v.Ciphertext = slices.Clone(v.Ciphertext)
	return v
}
func (r memoryReader) Project(k ProjectKey) (ProjectRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return ProjectRecord{}, e
	}
	v, ok := r.s.projects[k]
	if !ok {
		return ProjectRecord{}, ErrNotFound
	}
	return cloneProject(v), nil
}
func (r memoryReader) Projects(scope Scope) ([]ProjectRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ProjectRecord{}
	for k, v := range r.s.projects {
		if k.Scope == scope {
			out = append(out, cloneProject(v))
		}
	}
	slices.SortFunc(out, func(a, b ProjectRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutProject(v ProjectRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.projects[v.Key] = cloneProject(v)
	return nil
}
func (w memoryWriter) DeleteProject(k ProjectKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.projects, k)
	return nil
}
func (r memoryReader) Build(k BuildKey) (BuildRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return BuildRecord{}, e
	}
	v, ok := r.s.builds[k]
	if !ok {
		return BuildRecord{}, ErrNotFound
	}
	return cloneBuild(v), nil
}
func (r memoryReader) Builds(scope Scope) ([]BuildRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []BuildRecord{}
	for k, v := range r.s.builds {
		if k.Scope == scope {
			out = append(out, cloneBuild(v))
		}
	}
	slices.SortFunc(out, func(a, b BuildRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (w memoryWriter) PutBuild(v BuildRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.builds[v.Key] = cloneBuild(v)
	return nil
}
func (w memoryWriter) DeleteBuild(k BuildKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.builds, k)
	return nil
}
func (r memoryReader) Fleet(k FleetKey) (FleetRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return FleetRecord{}, e
	}
	v, ok := r.s.fleets[k]
	if !ok {
		return FleetRecord{}, ErrNotFound
	}
	return cloneFleet(v), nil
}
func (r memoryReader) Fleets(scope Scope) ([]FleetRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []FleetRecord{}
	for k, v := range r.s.fleets {
		if k.Scope == scope {
			out = append(out, cloneFleet(v))
		}
	}
	slices.SortFunc(out, func(a, b FleetRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (w memoryWriter) PutFleet(v FleetRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.fleets[v.Key] = cloneFleet(v)
	return nil
}
func (w memoryWriter) DeleteFleet(k FleetKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.fleets, k)
	return nil
}
func (r memoryReader) Credential(k CredentialKey) (CredentialRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return CredentialRecord{}, e
	}
	v, ok := r.s.credentials[k]
	if !ok {
		return CredentialRecord{}, ErrNotFound
	}
	return cloneCredential(v), nil
}
func (r memoryReader) Credentials(scope Scope) ([]CredentialRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []CredentialRecord{}
	for k, v := range r.s.credentials {
		if k.Scope == scope {
			out = append(out, cloneCredential(v))
		}
	}
	slices.SortFunc(out, func(a, b CredentialRecord) int {
		return cmp.Or(cmp.Compare(a.Key.ServerType, b.Key.ServerType), cmp.Compare(a.Key.AuthType, b.Key.AuthType))
	})
	return out, nil
}
func (w memoryWriter) PutCredential(v CredentialRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.credentials[v.Key] = cloneCredential(v)
	return nil
}
func (w memoryWriter) DeleteCredential(k CredentialKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.credentials, k)
	return nil
}
func compareScope(a, b Scope) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region))
}
func (r memoryReader) ActiveBuilds() ([]BuildRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []BuildRecord{}
	for _, v := range r.s.builds {
		if !complete(v) || v.DeleteRequested || v.CleanupPending {
			out = append(out, cloneBuild(v))
		}
	}
	slices.SortFunc(out, func(a, b BuildRecord) int {
		return cmp.Or(compareScope(a.Key.Scope, b.Key.Scope), cmp.Compare(a.Key.ID, b.Key.ID))
	})
	return out, nil
}
func (r memoryReader) AllFleets() ([]FleetRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []FleetRecord{}
	for _, v := range r.s.fleets {
		out = append(out, cloneFleet(v))
	}
	slices.SortFunc(out, func(a, b FleetRecord) int {
		return cmp.Or(compareScope(a.Key.Scope, b.Key.Scope), cmp.Compare(a.Key.Name, b.Key.Name))
	})
	return out, nil
}
