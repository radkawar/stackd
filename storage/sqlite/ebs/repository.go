// Package ebs persists snapshot layers, sparse block data and scheduled work.
package ebs

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/ebs"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
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

func (r reader) PendingSnapshotSources(scope domain.Scope) ([]domain.SnapshotKey, error) {
	ids, err := r.q.PendingSnapshotSources(r.ctx, sqlcgen.PendingSnapshotSourcesParams{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SnapshotKey, len(ids))
	for i, id := range ids {
		out[i] = domain.SnapshotKey{Scope: scope, ID: id}
	}
	return out, nil
}

func (r reader) VolumeSnapshotBlocksPending(key domain.VolumeKey) (bool, error) {
	return r.q.VolumeSnapshotBlocksPending(r.ctx, sqlcgen.VolumeSnapshotBlocksPendingParams{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ID: key.ID,
	})
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func nullableTime(v time.Time) sql.NullTime {
	if v.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}

func timeValue(v sql.NullTime) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return v.Time
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

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}
