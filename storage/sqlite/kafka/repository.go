// Package kafka persists typed MSK controls; native Kafka owns message bytes.
package kafka

import (
	"context"
	"database/sql"
	"errors"
	"math"
	domain "stackd/storage/kafka"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/kafka/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
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
func blob(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
