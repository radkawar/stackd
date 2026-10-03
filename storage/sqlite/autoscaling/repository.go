// Package autoscaling persists EC2 Auto Scaling configuration and durable work.
package autoscaling

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
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

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func rowLimit(n int) int64 {
	if n <= 0 {
		return -1
	}
	return int64(n)
}
func flag(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

// JSON binds only an ephemeral selection set; resource state is never JSON.
func namesJSON(names []string) string {
	data, _ := json.Marshal(names)
	return string(data)
}
func nullableString[T ~string](v *T) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*v), Valid: true}
}
func stringPointer[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.String)
	return &x
}
func nullableInt[T ~int32 | ~int64](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
func intPointer[T ~int32 | ~int64](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.Int64)
	return &x
}
func nullableBool[T ~bool](v *T) sql.NullBool {
	if v == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: bool(*v), Valid: true}
}
func boolPointer[T ~bool](v sql.NullBool) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.Bool)
	return &x
}
func nullableFloat[T ~float64](v *T) sql.NullFloat64 {
	if v == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: float64(*v), Valid: true}
}
func floatPointer[T ~float64](v sql.NullFloat64) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.Float64)
	return &x
}
func nullableTime(v *time.Time) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}
func timePointer(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}
func deadline(v time.Time) sql.NullTime {
	if v.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}
func groupKey(partition, account, region, name string) domain.GroupKey {
	return domain.GroupKey{Scope: domain.Scope{Partition: partition, AccountID: account, Region: region}, Name: name}
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
