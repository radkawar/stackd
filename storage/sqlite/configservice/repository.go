// Package configservice persists typed AWS Config state in the shared SQLite domain.
package configservice

import (
	"context"
	"database/sql"
	domain "stackd/storage/configservice"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/configservice/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

func (r reader) Tags(s domain.Scope, arn string) (map[string]string, error) {
	rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ARN: arn})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.Key] = row.Value
	}
	return out, nil
}

func (w writer) PutTags(s domain.Scope, arn string, tags map[string]string) error {
	if err := w.q.ClearTags(w.ctx, sqlcgen.ClearTagsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ARN: arn}); err != nil {
		return err
	}
	for key, value := range tags {
		if err := w.q.InsertTag(w.ctx, sqlcgen.InsertTagParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ARN: arn, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
