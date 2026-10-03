// Package ssmcommands persists managed nodes, immutable command inputs and agent results.
package ssmcommands

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
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
func storedTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
func (r reader) commandID(k domain.Key) (int64, error) {
	id, err := r.q.GetCommandID(r.ctx, sqlcgen.GetCommandIDParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, CommandID: k.ID})
	return id, missing(err)
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
