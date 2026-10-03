// Package sns persists typed SNS resources and retained delivery work.
package sns

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/sns"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
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

func pageLimit(limit int) int64 {
	if limit <= 0 {
		return -1
	}
	return int64(limit)
}

func utcPointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func (r reader) SigningKey() (domain.SigningKeyRecord, error) {
	v, err := r.q.GetSigningKey(r.ctx)
	if err != nil {
		return domain.SigningKeyRecord{}, missing(err)
	}
	return domain.SigningKeyRecord{ID: v.ID, PrivateKeyDER: v.PrivateKeyDer, CertificatePEM: v.CertificatePem}, nil
}

func (w writer) PutSigningKey(v domain.SigningKeyRecord) error {
	return w.q.PutSigningKey(w.ctx, sqlcgen.PutSigningKeyParams{ID: v.ID, PrivateKeyDer: v.PrivateKeyDER, CertificatePem: v.CertificatePEM})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}
