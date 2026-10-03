// Package kms stores KMS material and regional state in service-owned tables.
package kms

import (
	"context"
	"database/sql"

	domain "stackd/storage/kms"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/kms/internal/sqlcgen"
)

// Repository uses a database opened by sqlite.Open. Its owner must protect the
// database and backups as secret material, and close the stack before the DB.
type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}

func (r *Repository) Transact(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(transaction{reader{ctx, sqlcgen.New(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(transaction{reader{ctx, sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type transaction struct{ reader }

func (tx reader) Context() context.Context { return tx.ctx }

func (tx reader) Scopes() ([]domain.StorageScope, error) {
	rows, err := tx.q.ListScopes(tx.ctx)
	if err != nil {
		return nil, err
	}
	scopes := make([]domain.StorageScope, 0, len(rows))
	for _, row := range rows {
		scopes = append(scopes, domain.StorageScope{Partition: row.Partition, AccountID: row.Account, Region: row.Region})
	}
	return scopes, nil
}
