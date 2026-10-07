package ecr

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	domain "stackd/storage/ecr"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ecr/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func instant(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
func timestamp(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}
func binary(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

type jsonFields struct{ err error }

func (j *jsonFields) encode(v any) string {
	if j.err != nil {
		return ""
	}
	b, e := json.Marshal(v)
	j.err = e
	return string(b)
}
func (j *jsonFields) decode(text string, v any) {
	if j.err == nil {
		j.err = json.Unmarshal([]byte(text), v)
	}
}
func repositoryRow(v sqlcgen.EcrRepository) (domain.RepositoryRecord, error) {
	out := domain.RepositoryRecord{Key: domain.RepositoryKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, ARN: v.Arn, Created: timestamp(v.Created), Mutability: v.Mutability, EncryptionType: v.EncryptionType, KMSKeyID: v.KmsKeyID, DataKey: v.DataKey, ScanOnPush: v.ScanOnPush != 0, LifecyclePolicy: v.LifecyclePolicy, LifecycleDue: timestamp(v.LifecycleDue), LifecycleEvaluated: timestamp(v.LifecycleEvaluated), PreviewPolicy: v.PreviewPolicy, PreviewStatus: v.PreviewStatus, PreviewExpires: timestamp(v.PreviewExpires)}
	out.Policy.Document = v.Policy
	out.Ownership = v.Ownership
	j := jsonFields{}
	j.decode(v.Exclusions, &out.Exclusions)
	j.decode(v.Tags, &out.Tags)
	j.decode(v.PolicyPrincipals, &out.Policy.PrincipalIDs)
	j.decode(v.Grants, &out.Grants)
	j.decode(v.GrantTokens, &out.GrantTokens)
	j.decode(v.PreviewResults, &out.PreviewResults)
	return out, j.err
}
func (r reader) Repository(k domain.RepositoryKey) (domain.RepositoryRecord, error) {
	v, e := r.q.GetRepository(r.ctx, sqlcgen.GetRepositoryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.RepositoryRecord{}, missing(e)
	}
	return repositoryRow(v)
}
func repositoryRows(rows []sqlcgen.EcrRepository, err error) ([]domain.RepositoryRecord, error) {
	if err != nil {
		return nil, err
	}
	out := make([]domain.RepositoryRecord, 0, len(rows))
	for _, v := range rows {
		r, e := repositoryRow(v)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, nil
}
func (r reader) Repositories(k domain.Scope) ([]domain.RepositoryRecord, error) {
	rows, e := r.q.ListRepositories(r.ctx, sqlcgen.ListRepositoriesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	return repositoryRows(rows, e)
}
func (r reader) AllRepositories() ([]domain.RepositoryRecord, error) {
	rows, e := r.q.AllRepositories(r.ctx)
	return repositoryRows(rows, e)
}
func (w writer) PutRepository(v domain.RepositoryRecord) error {
	j := jsonFields{}
	p := sqlcgen.PutRepositoryParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, Arn: v.ARN, Created: instant(v.Created), Mutability: v.Mutability, Exclusions: j.encode(v.Exclusions), Tags: j.encode(v.Tags), Policy: v.Policy.Document, PolicyPrincipals: j.encode(v.Policy.PrincipalIDs), EncryptionType: v.EncryptionType, KmsKeyID: v.KMSKeyID, DataKey: binary(v.DataKey), Grants: j.encode(v.Grants), GrantTokens: j.encode(v.GrantTokens), LifecyclePolicy: v.LifecyclePolicy, LifecycleDue: instant(v.LifecycleDue), LifecycleEvaluated: instant(v.LifecycleEvaluated), PreviewPolicy: v.PreviewPolicy, PreviewStatus: v.PreviewStatus, PreviewResults: j.encode(v.PreviewResults), PreviewExpires: instant(v.PreviewExpires), Ownership: v.Ownership}
	if v.ScanOnPush {
		p.ScanOnPush = 1
	}
	if j.err != nil {
		return j.err
	}
	return w.q.PutRepository(w.ctx, p)
}
func (w writer) DeleteRepository(k domain.RepositoryKey) error {
	return w.q.DeleteRepository(w.ctx, sqlcgen.DeleteRepositoryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func (r reader) Registry(k domain.Scope) (domain.RegistryRecord, error) {
	v, e := r.q.GetRegistry(r.ctx, sqlcgen.GetRegistryParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return domain.RegistryRecord{}, missing(e)
	}
	out := domain.RegistryRecord{Scope: k}
	out.PolicyOwnership, out.ReplicationOwnership, out.ScanningOwnership = v.PolicyOwnership, v.ReplicationOwnership, v.ScanningOwnership
	out.Policy.Document = v.Policy
	j := jsonFields{}
	j.decode(v.PolicyPrincipals, &out.Policy.PrincipalIDs)
	j.decode(v.Scanning, &out.Scanning)
	j.decode(v.Replication, &out.Replication)
	return out, j.err
}
func (w writer) PutRegistry(v domain.RegistryRecord) error {
	j := jsonFields{}
	p := sqlcgen.PutRegistryParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Policy: v.Policy.Document, PolicyPrincipals: j.encode(v.Policy.PrincipalIDs), Scanning: j.encode(v.Scanning), Replication: j.encode(v.Replication)}
	p.PolicyOwnership, p.ReplicationOwnership, p.ScanningOwnership = v.PolicyOwnership, v.ReplicationOwnership, v.ScanningOwnership
	if j.err != nil {
		return j.err
	}
	return w.q.PutRegistry(w.ctx, p)
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}

func (r reader) AllRegistries() ([]domain.RegistryRecord, error) {
	rows, err := r.q.AllRegistries(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.RegistryRecord, 0, len(rows))
	for _, v := range rows {
		record := domain.RegistryRecord{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}}
		record.PolicyOwnership, record.ReplicationOwnership, record.ScanningOwnership = v.PolicyOwnership, v.ReplicationOwnership, v.ScanningOwnership
		record.Policy.Document = v.Policy
		j := jsonFields{}
		j.decode(v.PolicyPrincipals, &record.Policy.PrincipalIDs)
		j.decode(v.Scanning, &record.Scanning)
		j.decode(v.Replication, &record.Replication)
		if j.err != nil {
			return nil, j.err
		}
		out = append(out, record)
	}
	return out, nil
}
