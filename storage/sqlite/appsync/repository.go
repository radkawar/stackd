// Package appsync stores authoritative AppSync definitions in typed SQLC tables.
package appsync

import (
	"context"
	"database/sql"
	"errors"
	api "stackd/internal/awsapi/appsync"
	domain "stackd/storage/appsync"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/appsync/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
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
func deleted(n int64, e error) error {
	if e != nil {
		return e
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func val[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func str[T ~string](p *T) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*p), Valid: true}
}
func number[T ~int32 | ~int64](p *T) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}
func boolean[T ~bool](p *T) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	v := int64(0)
	if bool(*p) {
		v = 1
	}
	return sql.NullInt64{Int64: v, Valid: true}
}
func text[T ~string](p **T, v string) { x := T(v); *p = &x }
func readString[T ~string](p **T, v sql.NullString) {
	if v.Valid {
		text(p, v.String)
	}
}
func readNumber[T ~int32 | ~int64](p **T, v sql.NullInt64) {
	if v.Valid {
		x := T(v.Int64)
		*p = &x
	}
}
func readBoolean(p **api.Boolean, v sql.NullInt64) {
	if v.Valid {
		x := api.Boolean(v.Int64 != 0)
		*p = &x
	}
}
func (r reader) API(k domain.Key) (domain.APIRecord, error) {
	p, e := r.APIByID(k.ID)
	if e == nil && p.Key != k {
		return domain.APIRecord{}, domain.ErrNotFound
	}
	return p, e
}
func (r reader) APIByID(id string) (domain.APIRecord, error) {
	v, e := r.q.GetAPI(r.ctx, id)
	if e != nil {
		return domain.APIRecord{}, missing(e)
	}
	return r.decodeAPI(v)
}
func (r reader) APIs() ([]domain.APIRecord, error) {
	rows, e := r.q.ListAPI(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.APIRecord, 0, len(rows))
	for _, v := range rows {
		p, e := r.decodeAPI(v)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (r writer) DeleteAPI(k domain.Key) error {
	if _, e := r.API(k); e != nil {
		return e
	}
	return deleted(r.q.DeleteAPI(r.ctx, k.ID))
}
func (r writer) DeleteDataSource(k domain.Key, name string) error {
	if _, e := r.API(k); e != nil {
		return e
	}
	if e := domain.CheckDeleteDataSource(r, k, name); e != nil {
		return e
	}
	return deleted(r.q.DeleteDataSource(r.ctx, sqlcgen.DeleteDataSourceParams{ApiID: k.ID, Name: name}))
}
func (r writer) DeleteFunction(k domain.Key, id string) error {
	if _, e := r.API(k); e != nil {
		return e
	}
	if e := domain.CheckDeleteFunction(r, k, id); e != nil {
		return e
	}
	return deleted(r.q.DeleteFunction(r.ctx, sqlcgen.DeleteFunctionParams{ApiID: k.ID, FunctionID: id}))
}
func (r writer) DeleteResolver(k domain.Key, typeName, fieldName string) error {
	if _, e := r.API(k); e != nil {
		return e
	}
	return deleted(r.q.DeleteResolver(r.ctx, sqlcgen.DeleteResolverParams{ApiID: k.ID, TypeName: typeName, FieldName: fieldName}))
}
func (r writer) DeleteAPIKey(k domain.Key, id string) error {
	if _, e := r.API(k); e != nil {
		return e
	}
	return deleted(r.q.DeleteAPIKey(r.ctx, sqlcgen.DeleteAPIKeyParams{ApiID: k.ID, KeyID: id}))
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
