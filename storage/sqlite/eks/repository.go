// Package eks persists EKS intent and access records in the shared SQLite transaction domain.
package eks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

// Repository retains cluster generations, deadlines and access identity across
// restart. Borrowed callbacks join the owner's commit; Attempt uses a savepoint.
// Access mutation tokens remain retained until their exact entry or cluster is
// deleted, allowing service replay checks after subsequent access revocations.
type Repository struct{ db *sql.DB }

// New uses the caller-owned migrated database and does not take ownership of Close.
func New(db *sql.DB) *Repository { return &Repository{db: db} }
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
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
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
func bit(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

// Only collection fields use JSON; record identity and scalar intent have typed columns.
func encodeStrings(v []string) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
func encodeTags(v map[string]string) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

var (
	_ domain.Repository  = (*Repository)(nil)
	_ domain.Transaction = writer{}
)
