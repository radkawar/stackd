// Package firehose persists typed Firehose metadata and retained delivery work.
package firehose

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/firehose"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/firehose/internal/sqlcgen"
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

func nullableInteger[T ~int32 | ~int64](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

func integerPointer[T ~int32 | ~int64](v sql.NullInt64) *T {
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
	x := v.Time.UTC()
	return &x
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}
