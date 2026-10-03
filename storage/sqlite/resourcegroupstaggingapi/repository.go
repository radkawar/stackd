// Package resourcegroupstaggingapi persists inventory membership and report intents.
package resourcegroupstaggingapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	domain "stackd/storage/resourcegroupstaggingapi"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/resourcegroupstaggingapi/internal/sqlcgen"
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
func (r reader) Memberships(scope domain.Scope, service string) ([]domain.Membership, error) {
	rows, err := r.q.ListMemberships(r.ctx, sqlcgen.ListMembershipsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ServiceFilter: service})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Membership, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Membership{Scope: scope, Service: row.Service, ARN: row.Arn})
	}
	return out, nil
}
func (w writer) PutMembership(m domain.Membership) error {
	return w.q.PutMembership(w.ctx, sqlcgen.PutMembershipParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, Service: m.Service, Arn: m.ARN})
}
func (w writer) DeleteMembership(m domain.Membership) error {
	return w.q.DeleteMembership(w.ctx, sqlcgen.DeleteMembershipParams{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, Service: m.Service, Arn: m.ARN})
}
func reportRecord(row sqlcgen.ResourcegroupstaggingapiReport) (domain.Report, error) {
	report := domain.Report{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Version: uint64(row.Version), OrganizationID: row.OrganizationID, Bucket: row.Bucket, ObjectKey: row.ObjectKey, Status: row.Status, ErrorMessage: row.ErrorMessage, StartedAt: time.Unix(0, row.StartedAt).UTC(), Due: time.Unix(0, row.Due).UTC()}
	if row.Status != "RUNNING" {
		report.CompletedAt = time.Unix(0, row.CompletedAt).UTC()
	}
	err := json.Unmarshal([]byte(row.CallerJson), &report.Caller)
	return report, err
}
func (r reader) Report(scope domain.Scope) (domain.Report, bool, error) {
	row, err := r.q.GetReport(r.ctx, sqlcgen.GetReportParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Report{}, false, nil
	}
	if err != nil {
		return domain.Report{}, false, err
	}
	report, err := reportRecord(row)
	return report, err == nil, err
}
func (r reader) NextReport() (domain.Report, bool, error) {
	row, err := r.q.NextReport(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Report{}, false, nil
	}
	if err != nil {
		return domain.Report{}, false, err
	}
	report, err := reportRecord(row)
	return report, err == nil, err
}
func (w writer) PutReport(report domain.Report) error {
	caller, err := json.Marshal(report.Caller)
	if err != nil {
		return err
	}
	completed := int64(0)
	if !report.CompletedAt.IsZero() {
		completed = report.CompletedAt.UnixNano()
	}
	return w.q.PutReport(w.ctx, sqlcgen.PutReportParams{Partition: report.Partition, AccountID: report.AccountID, Region: report.Region, Version: int64(report.Version), OrganizationID: report.OrganizationID, Bucket: report.Bucket, ObjectKey: report.ObjectKey, Status: report.Status, ErrorMessage: report.ErrorMessage, StartedAt: report.StartedAt.UnixNano(), CompletedAt: completed, Due: report.Due.UnixNano(), CallerJson: string(caller)})
}

var _ domain.Repository = (*Repository)(nil)
