// Package cloudformation retains deployments in the shared SQLite transaction domain.
package cloudformation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
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
func signed(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("cloudformation sequence exceeds SQLite integer range: %d", value)
	}
	return int64(value), nil
}
func encodeDocument(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}
func decodeDocument(value string, into any) error { return json.Unmarshal([]byte(value), into) }
func nullableTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

var _ domain.Repository = (*Repository)(nil)
