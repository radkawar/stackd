// Package xray persists regional trace segments and resource policies.
package xray

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"stackd/storage/sqlite"
	"stackd/storage/sqlite/xray/internal/sqlcgen"
	domain "stackd/storage/xray"
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

func segment(v sqlcgen.XraySegment) domain.SegmentRecord {
	out := domain.SegmentRecord{
		Key:      domain.SegmentKey{TraceKey: domain.TraceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.TraceID}, ID: v.ID},
		ParentID: v.ParentID, Subsegment: v.Subsegment, InlineOrder: v.InlineOrder, Start: v.StartTime,
		InProgress: v.InProgress, Document: v.Document, Received: v.Received,
		ReceivedRevision: v.ReceivedRevision, Revision: v.Revision,
	}
	if v.EndTime.Valid {
		out.End = new(v.EndTime.Float64)
	}
	if v.Completed.Valid {
		out.Completed = new(v.Completed.Time)
	}
	return out
}

func (r reader) Segment(k domain.SegmentKey) (domain.SegmentRecord, error) {
	v, err := r.q.GetSegment(r.ctx, sqlcgen.GetSegmentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TraceID: k.TraceKey.ID, ID: k.ID})
	return segment(v), missing(err)
}

func (r reader) TraceSegments(k domain.TraceKey) ([]domain.SegmentRecord, error) {
	rows, err := r.q.ListTraceSegments(r.ctx, sqlcgen.ListTraceSegmentsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TraceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SegmentRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, segment(row))
	}
	return out, nil
}

func (r reader) EarliestSegmentReceipt() (time.Time, bool, error) {
	received, err := r.q.EarliestSegmentReceipt(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	return received, err == nil, err
}

func (w writer) PutSegment(v domain.SegmentRecord) error {
	var end sql.NullFloat64
	if v.End != nil {
		end = sql.NullFloat64{Float64: *v.End, Valid: true}
	}
	var completed sql.NullTime
	if v.Completed != nil {
		completed = sql.NullTime{Time: *v.Completed, Valid: true}
	}
	return w.q.PutSegment(w.ctx, sqlcgen.PutSegmentParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, TraceID: v.Key.TraceKey.ID, ID: v.Key.ID, ParentID: v.ParentID, Subsegment: v.Subsegment, InlineOrder: v.InlineOrder, StartTime: v.Start, EndTime: end, InProgress: v.InProgress, Document: v.Document, Received: v.Received, Completed: completed, ReceivedRevision: v.ReceivedRevision, Revision: v.Revision})
}

func (w writer) DeleteExpiredSegments(cutoff time.Time) error {
	rows, err := w.q.DeleteExpiredSegments(w.ctx, cutoff)
	if err != nil {
		return err
	}
	affected := make(map[sqlcgen.DeleteEmptyTraceParams]struct{}, len(rows))
	for _, row := range rows {
		affected[sqlcgen.DeleteEmptyTraceParams(row)] = struct{}{}
	}
	for key := range affected {
		if err := w.q.DeleteEmptyTrace(w.ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) policy(v sqlcgen.XrayResourcePolicy) (domain.PolicyRecord, error) {
	out := domain.PolicyRecord{Key: domain.PolicyKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Revision: v.Revision, Updated: v.Updated}
	out.Policy.Document = v.Document
	rows, err := r.q.GetPolicyPrincipals(r.ctx, sqlcgen.GetPolicyPrincipalsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, PolicyName: v.Name})
	if err != nil {
		return domain.PolicyRecord{}, err
	}
	out.Policy.PrincipalIDs = make(map[string]string, len(rows))
	for _, row := range rows {
		out.Policy.PrincipalIDs[row.Arn] = row.PrincipalID
	}
	return out, nil
}

func (r reader) ResourcePolicies(k domain.Scope) ([]domain.PolicyRecord, error) {
	rows, err := r.q.ListResourcePolicies(r.ctx, sqlcgen.ListResourcePoliciesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PolicyRecord, 0, len(rows))
	for _, row := range rows {
		policy, err := r.policy(row)
		if err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, nil
}

func (w writer) PutResourcePolicy(v domain.PolicyRecord) error {
	k := v.Key
	if err := w.q.PutResourcePolicy(w.ctx, sqlcgen.PutResourcePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Document: v.Policy.Document, Revision: v.Revision, Updated: v.Updated}); err != nil {
		return err
	}
	if err := w.q.DeletePolicyPrincipals(w.ctx, sqlcgen.DeletePolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PolicyName: k.Name}); err != nil {
		return err
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PolicyName: k.Name, Arn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteResourcePolicy(k domain.PolicyKey) error {
	return w.q.DeleteResourcePolicy(w.ctx, sqlcgen.DeleteResourcePolicyParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
