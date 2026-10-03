// Package ssm persists typed Parameter Store metadata, value bytes and scheduled work.
package ssm

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ssm/internal/sqlcgen"
	domain "stackd/storage/ssm"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx: ctx, q: sqlcgen.New(tx)})
	})
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
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
func policyTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
func (r reader) parameterID(k domain.ParameterKey) (int64, error) {
	id, err := r.q.GetParameterID(r.ctx, sqlcgen.GetParameterIDParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	return id, missing(err)
}
func (r reader) versionRow(k domain.VersionKey) (sqlcgen.SsmVersion, error) {
	id, err := r.parameterID(k.Parameter)
	if err != nil {
		return sqlcgen.SsmVersion{}, err
	}
	v, err := r.q.GetVersion(r.ctx, sqlcgen.GetVersionParams{ParentID: id, Version: k.Version})
	return v, missing(err)
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
