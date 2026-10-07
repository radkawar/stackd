// Package codepipeline persists normalized pipeline intent and artifact references
// in the shared SQLite transaction domain. S3 remains the only artifact byte owner.
package codepipeline

import (
	"context"
	"database/sql"
	domain "stackd/storage/codepipeline"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/codepipeline/internal/sqlcgen"
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
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
func instant(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
func flag(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func value[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return
}
func text[T ~string](p *T) string { return string(value(p)) }
func optional[T ~string](s string) *T {
	if s == "" {
		return nil
	}
	return new(T(s))
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}

func (r reader) Pipelines(sc domain.Scope) ([]domain.Pipeline, error) {
	rows, err := r.q.ListPipelines(r.ctx, sqlcgen.ListPipelinesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Pipeline, 0, len(rows))
	for _, row := range rows {
		v := domain.Pipeline{Scope: sc, Name: row.Name, Incarnation: row.Incarnation, Ownership: row.Ownership, LastUpdate: row.LastUpdate, Version: int32(row.Version), CreatedAt: instant(row.CreatedAt), UpdatedAt: instant(row.UpdatedAt), PollingDisabledAt: instant(row.PollingDisabledAt), Tags: map[string]string{}}
		tags, err := r.q.ListTags(r.ctx, row.Incarnation)
		if err != nil {
			return nil, err
		}
		for _, t := range tags {
			v.Tags[t.TagKey] = t.TagValue
		}
		transitions, err := r.q.ListTransitions(r.ctx, row.Incarnation)
		if err != nil {
			return nil, err
		}
		for _, t := range transitions {
			v.Transitions = append(v.Transitions, domain.Transition{Stage: t.StageName, Type: t.TransitionType, Disabled: t.Disabled != 0, Reason: t.Reason, ChangedBy: t.ChangedBy, ChangedAt: instant(t.ChangedAt)})
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutPipeline(v domain.Pipeline) error {
	if err := w.q.PutPipelines(w.ctx, sqlcgen.PutPipelinesParams{Ownership: v.Ownership, LastUpdate: v.LastUpdate, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, Incarnation: v.Incarnation, Version: int64(v.Version), CreatedAt: nanos(v.CreatedAt), UpdatedAt: nanos(v.UpdatedAt), PollingDisabledAt: nanos(v.PollingDisabledAt)}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, v.Incarnation); err != nil {
		return err
	}
	for k, t := range v.Tags {
		if err := w.q.PutTags(w.ctx, sqlcgen.PutTagsParams{Incarnation: v.Incarnation, TagKey: k, TagValue: t}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteTransitions(w.ctx, v.Incarnation); err != nil {
		return err
	}
	for _, t := range v.Transitions {
		if err := w.q.PutTransitions(w.ctx, sqlcgen.PutTransitionsParams{Incarnation: v.Incarnation, StageName: t.Stage, TransitionType: t.Type, Disabled: flag(t.Disabled), Reason: t.Reason, ChangedBy: t.ChangedBy, ChangedAt: nanos(t.ChangedAt)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeletePipeline(sc domain.Scope, name string) error {
	rows, err := w.Pipelines(sc)
	if err != nil {
		return err
	}
	for _, v := range rows {
		if v.Name != name {
			continue
		}
		if err = w.q.FenceDeletedExecutions(w.ctx, v.Incarnation); err != nil {
			return err
		}
		if err = w.q.DeleteTags(w.ctx, v.Incarnation); err != nil {
			return err
		}
		if err = w.q.DeleteTransitions(w.ctx, v.Incarnation); err != nil {
			return err
		}
		if err = w.DeleteSourcePolls(sc, v.Incarnation); err != nil {
			return err
		}
		return w.q.DeletePipeline(w.ctx, sqlcgen.DeletePipelineParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Name: name})
	}
	return nil
}
