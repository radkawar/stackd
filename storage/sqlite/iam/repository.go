// Package iam stores IAM identities, policies and credentials in service-owned
// SQLite tables. Authentication and policy changes share the native transaction.
package iam

import (
	"context"
	"database/sql"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

// Repository joins Account, Organizations, KMS and SQS transactions on the same
// database. The caller owns the database and must close its stack first.
type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.ReadTx) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.WriteTx) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.WriteTx) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
