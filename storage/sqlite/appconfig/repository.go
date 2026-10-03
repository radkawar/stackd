// Package appconfig persists typed AppConfig state in the shared SQLite domain.
// Configuration bytes are BLOBs; ordered validators, monitors, extension actions,
// parameters and deployment events live in normalized child tables. Deployed
// content and action snapshots survive changes to their source catalogs.
package appconfig

import (
	"context"
	"database/sql"
	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
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

// SQL NULL is not configuration content; the empty payload is a zero-length BLOB.
func contentBytes(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
