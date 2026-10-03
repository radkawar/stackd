// Package cognitoidp persists user pools and their authentication state.
package cognitoidp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

// New borrows db. The owner of the shared database remains responsible for closing it.
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
	return new(T(v.String))
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
	return new(T(v.Int64))
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
	return new(T(v.Bool))
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
	return new(v.Time.UTC())
}

// Each field is one generated nested configuration, never a resource record.
type jsonWriteField struct {
	target *[]byte
	value  any
}

func marshalFields(fields ...jsonWriteField) error {
	for _, field := range fields {
		data, err := json.Marshal(field.value)
		if err != nil {
			return err
		}
		*field.target = data
	}
	return nil
}

type jsonReadField struct {
	source []byte
	target any
}

func unmarshalFields(fields ...jsonReadField) error {
	for _, field := range fields {
		if err := json.Unmarshal(field.source, field.target); err != nil {
			return err
		}
	}
	return nil
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
