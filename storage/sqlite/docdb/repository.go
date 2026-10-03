// Package docdb persists typed control intent; engine volumes own document bytes.
package docdb

import (
	"context"
	"database/sql"
	"errors"
	"math"
	domain "stackd/storage/docdb"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/docdb/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
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
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func timeValue(t time.Time) int64 {
	if t.IsZero() {
		return math.MinInt64
	}
	return t.UnixNano()
}
func readTime(n int64) time.Time {
	if n == math.MinInt64 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
func bit(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func blob(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
func (r reader) tags(k domain.Key) (map[string]string, error) {
	rows, e := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.TagKey] = row.TagValue
	}
	return out, nil
}
func (w writer) deleteTags(k domain.Key) error {
	return w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
func (w writer) putTags(k domain.Key, tags map[string]string) error {
	if e := w.deleteTags(k); e != nil {
		return e
	}
	for key, value := range tags {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, TagKey: key, TagValue: value}); e != nil {
			return e
		}
	}
	return nil
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
