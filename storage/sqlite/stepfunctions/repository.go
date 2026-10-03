// Package stepfunctions persists normalized workflow resources and execution state.
package stepfunctions

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/internal/services/stepfunctions"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/stepfunctions/internal/sqlcgen"
)

type Repository struct {
	db      *sql.DB
	queries *sqlcgen.Queries
}

// New prepares the service-owned queries before any repository transaction.
// The caller owns db; closing it releases the underlying prepared statements.
func New(ctx context.Context, db *sql.DB) (*Repository, error) {
	queries, err := sqlcgen.Prepare(ctx, db)
	if err != nil {
		return nil, err
	}
	return &Repository{db: db, queries: queries}, nil
}

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx: ctx, q: r.queries.WithTx(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: r.queries.WithTx(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: r.queries.WithTx(tx)}})
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

func deleted(rows int64, err error) error {
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func nullableTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

func timePointer(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	return new(t.Time)
}

func encryptedPayload(dataKey, content []byte) *domain.EncryptedPayload {
	if dataKey == nil && content == nil {
		return nil
	}
	return &domain.EncryptedPayload{DataKey: dataKey, Content: content}
}

func encryptedColumns(v *domain.EncryptedPayload) (dataKey, content []byte) {
	if v == nil {
		return nil, nil
	}
	dataKey, content = v.DataKey, v.Content
	if dataKey == nil && content == nil {
		// An empty BLOB distinguishes a present payload from SQL NULLs.
		dataKey = []byte{}
	}
	return dataKey, content
}

func (w writer) reclaim(scope domain.Scope, revisionID string) error {
	return w.q.DeleteUnreferencedRevision(w.ctx, sqlcgen.DeleteUnreferencedRevisionParams{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ID: revisionID,
	})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
