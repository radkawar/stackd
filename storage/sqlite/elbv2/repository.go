// Package elbv2 persists typed ALB resources, ownership and health/drain intent.
package elbv2

import (
	"context"
	"database/sql"
	"errors"
	"math"
	api "stackd/internal/awsapi/elbv2"
	domain "stackd/storage/elbv2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/elbv2/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
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
func (w writer) NextID() (uint64, error) { n, e := w.q.NextID(w.ctx); return uint64(n), e }
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
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func intValue[T ~int32 | ~int64](v *T) int64 {
	if v == nil {
		return 0
	}
	return int64(*v)
}
func text[T ~string](p **T, v string) {
	if v != "" {
		x := T(v)
		*p = &x
	}
}
func number[T ~int32 | ~int64](p **T, v int64) { x := T(v); *p = &x }
func boolean[T ~bool](p **T, v int64)          { x := T(v != 0); *p = &x }
func flag(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func boolValue[T ~bool](v *T) int64 {
	if v != nil && *v {
		return 1
	}
	return 0
}
func (r reader) tags(sc domain.Scope, a string) (api.TagList, error) {
	rows, e := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
	if e != nil {
		return nil, e
	}
	out := make(api.TagList, 0, len(rows))
	for _, row := range rows {
		var t api.Tag
		text(&t.Key, row.Key)
		v := api.TagValue(row.Value)
		t.Value = &v
		out = append(out, t)
	}
	return out, nil
}
func (w writer) putTags(sc domain.Scope, a string, tags api.TagList) error {
	if e := w.deleteTags(sc, a); e != nil {
		return e
	}
	for _, t := range tags {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a, Key: value(t.Key), Value: value(t.Value)}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) deleteTags(sc domain.Scope, a string) error {
	return w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: a})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
