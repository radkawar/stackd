// Package elasticache persists scoped typed cache intent in the shared SQL domain.
package elasticache

import (
	"context"
	"database/sql"
	"errors"
	"math"
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
	"time"
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
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func timeValue(v time.Time) int64 {
	if v.IsZero() {
		return math.MinInt64
	}
	return v.UnixNano()
}
func readTime(v int64) time.Time {
	if v == math.MinInt64 {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}
func bit(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
