// Package opensearch persists typed domain intent; native engine bytes remain in owned volumes.
package opensearch

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	domain "stackd/storage/opensearch"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/opensearch/internal/sqlcgen"
)

type Repository struct {
	db *sql.DB
}

func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct {
	reader
}

func (r reader) Context() context.Context {
	return r.ctx
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
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

var (
	_ domain.Repository  = (*Repository)(nil)
	_ domain.Transaction = writer{}
)
