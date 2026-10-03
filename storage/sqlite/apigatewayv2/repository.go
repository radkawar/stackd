// Package apigatewayv2 persists HTTP API configuration and immutable deployments.
package apigatewayv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/apigatewayv2/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

// New borrows the shared database and joins its native transaction domain.
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
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func integer(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

// JSON columns contain domain collections and authorizer policy/context data.
// Resource configuration and deployment relations remain typed SQL columns.
func encode(v any) ([]byte, error)   { return json.Marshal(v) }
func decode(v []byte, out any) error { return json.Unmarshal(v, out) }

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
