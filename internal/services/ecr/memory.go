package ecr

import (
	"cmp"
	"context"
	"maps"
	"slices"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
	"stackd/storage/memory"
	"time"
)

type memoryState struct {
	repositories map[RepositoryKey]RepositoryRecord
	registries   map[Scope]RegistryRecord
	images       map[ImageKey]ImageRecord
	blobs        map[ImageKey]BlobRecord
	uploads      map[UploadKey]UploadRecord
	tokens       map[string]TokenRecord
	replications map[ReplicationKey]ReplicationRecord
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(d *memory.Domain) *MemoryRepository {
	initial := memoryState{repositories: map[RepositoryKey]RepositoryRecord{}, registries: map[Scope]RegistryRecord{}, images: map[ImageKey]ImageRecord{}, blobs: map[ImageKey]BlobRecord{}, uploads: map[UploadKey]UploadRecord{}, tokens: map[string]TokenRecord{}, replications: map[ReplicationKey]ReplicationRecord{}}
	return &MemoryRepository{memory.New(d, initial, func(s memoryState) memoryState {
		s.repositories = maps.Clone(s.repositories)
		s.registries = maps.Clone(s.registries)
		s.images = maps.Clone(s.images)
		s.blobs = maps.Clone(s.blobs)
		s.uploads = maps.Clone(s.uploads)
		s.tokens = maps.Clone(s.tokens)
		s.replications = maps.Clone(s.replications)
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
func cloneRepository(v RepositoryRecord) RepositoryRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	v.DataKey = slices.Clone(v.DataKey)
	v.Grants = slices.Clone(v.Grants)
	v.GrantTokens = slices.Clone(v.GrantTokens)
	v.Exclusions = api.CloneImageTagMutabilityExclusionFilters(v.Exclusions)
	v.PreviewResults = api.CloneLifecyclePolicyPreviewResultList(v.PreviewResults)
	return v
}
func cloneRegistry(v RegistryRecord) RegistryRecord {
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	v.Scanning = api.CloneRegistryScanningConfiguration(v.Scanning)
	v.Replication = api.CloneReplicationConfiguration(v.Replication)
	return v
}
func cloneImage(v ImageRecord) ImageRecord {
	v.Payload = slices.Clone(v.Payload)
	v.Tags = slices.Clone(v.Tags)
	v.References = slices.Clone(v.References)
	v.Layers = slices.Clone(v.Layers)
	v.Findings = api.CloneImageScanFindingList(v.Findings)
	return v
}
func (r memoryReader) Repository(k RepositoryKey) (RepositoryRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return RepositoryRecord{}, e
	}
	v, ok := r.s.repositories[k]
	if !ok {
		return RepositoryRecord{}, ErrNotFound
	}
	return cloneRepository(v), nil
}
func (r memoryReader) Repositories(scope Scope) ([]RepositoryRecord, error) {
	all, e := r.AllRepositories()
	if e != nil {
		return nil, e
	}
	return slices.DeleteFunc(all, func(v RepositoryRecord) bool { return v.Key.Scope != scope }), nil
}
func (r memoryReader) AllRepositories() ([]RepositoryRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := make([]RepositoryRecord, 0, len(r.s.repositories))
	for _, v := range r.s.repositories {
		out = append(out, cloneRepository(v))
	}
	slices.SortFunc(out, func(a, b RepositoryRecord) int { return cmp.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (r memoryReader) Registry(k Scope) (RegistryRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return RegistryRecord{}, e
	}
	v, ok := r.s.registries[k]
	if !ok {
		return RegistryRecord{}, ErrNotFound
	}
	return cloneRegistry(v), nil
}
func (r memoryReader) Image(k ImageKey) (ImageRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return ImageRecord{}, e
	}
	v, ok := r.s.images[k]
	if !ok {
		return ImageRecord{}, ErrNotFound
	}
	return cloneImage(v), nil
}
func (r memoryReader) Images(k RepositoryKey) ([]ImageRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return nil, e
	}
	out := []ImageRecord{}
	for key, v := range r.s.images {
		if key.Repository == k {
			out = append(out, cloneImage(v))
		}
	}
	slices.SortFunc(out, func(a, b ImageRecord) int { return cmp.Compare(a.Key.Digest, b.Key.Digest) })
	return out, nil
}
func (r memoryReader) Blob(k ImageKey) (BlobRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return BlobRecord{}, e
	}
	v, ok := r.s.blobs[k]
	if !ok {
		return BlobRecord{}, ErrNotFound
	}
	v.Payload = slices.Clone(v.Payload)
	return v, nil
}
func (r memoryReader) Upload(k UploadKey) (UploadRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return UploadRecord{}, e
	}
	v, ok := r.s.uploads[k]
	if !ok {
		return UploadRecord{}, ErrNotFound
	}
	v.Payload = slices.Clone(v.Payload)
	return v, nil
}
func (r memoryReader) Token(k string) (TokenRecord, error) {
	if e := r.tx.Check(false); e != nil {
		return TokenRecord{}, e
	}
	v, ok := r.s.tokens[k]
	if !ok {
		return TokenRecord{}, ErrNotFound
	}
	v.Identity = awsctx.Clone(v.Identity)
	return v, nil
}
func (w memoryWriter) PutRepository(v RepositoryRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.repositories[v.Key] = cloneRepository(v)
	return nil
}
func (w memoryWriter) PutRegistry(v RegistryRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.registries[v.Scope] = cloneRegistry(v)
	return nil
}
func (w memoryWriter) PutImage(v ImageRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	w.s.images[v.Key] = cloneImage(v)
	return nil
}
func (w memoryWriter) PutBlob(v BlobRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	v.Payload = slices.Clone(v.Payload)
	w.s.blobs[v.Key] = v
	return nil
}
func (w memoryWriter) PutUpload(v UploadRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	v.Payload = slices.Clone(v.Payload)
	w.s.uploads[v.Key] = v
	return nil
}
func (w memoryWriter) PutToken(v TokenRecord) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	v.Identity = awsctx.Clone(v.Identity)
	w.s.tokens[v.Hash] = v
	return nil
}
func (w memoryWriter) DeleteImage(k ImageKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.images, k)
	return nil
}
func (w memoryWriter) DeleteUpload(k UploadKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.uploads, k)
	return nil
}
func (w memoryWriter) DeleteExpiredTokens(now time.Time) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	for k, v := range w.s.tokens {
		if !now.Before(v.Expires) {
			delete(w.s.tokens, k)
		}
	}
	return nil
}
func (w memoryWriter) DeleteRepository(k RepositoryKey) error {
	if e := w.tx.Check(true); e != nil {
		return e
	}
	delete(w.s.repositories, k)
	for key := range w.s.images {
		if key.Repository == k {
			delete(w.s.images, key)
		}
	}
	for key := range w.s.blobs {
		if key.Repository == k {
			delete(w.s.blobs, key)
		}
	}
	for key := range w.s.uploads {
		if key.Repository == k {
			delete(w.s.uploads, key)
		}
	}
	return nil
}
func cloneReplication(v ReplicationRecord) ReplicationRecord {
	v.Tags = slices.Clone(v.Tags)
	v.Origin = awsctx.Clone(v.Origin)
	return v
}
func (r memoryReader) Replications() ([]ReplicationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]ReplicationRecord, 0, len(r.s.replications))
	for _, v := range r.s.replications {
		out = append(out, cloneReplication(v))
	}
	slices.SortFunc(out, func(a, b ReplicationRecord) int {
		if n := a.Due.Compare(b.Due); n != 0 {
			return n
		}
		return cmp.Compare(replicationID(a.Key), replicationID(b.Key))
	})
	return out, nil
}
func (w memoryWriter) PutReplication(v ReplicationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.replications[v.Key] = cloneReplication(v)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)

func (r memoryReader) AllRegistries() ([]RegistryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]RegistryRecord, 0, len(r.s.registries))
	for _, v := range r.s.registries {
		rows = append(rows, cloneRegistry(v))
	}
	slices.SortFunc(rows, func(a, b RegistryRecord) int {
		if n := cmp.Compare(a.Scope.Partition, b.Scope.Partition); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Scope.AccountID, b.Scope.AccountID); n != 0 {
			return n
		}
		return cmp.Compare(a.Scope.Region, b.Scope.Region)
	})
	return rows, nil
}
