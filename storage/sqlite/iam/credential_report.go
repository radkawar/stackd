package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) CredentialReport(scope domain.Scope) (domain.CredentialReportRecord, error) {
	var result domain.CredentialReportRecord
	row, err := r.q.GetCredentialReport(r.ctx, sqlcgen.GetCredentialReportParams{Partition: scope.Partition, Account: scope.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.CredentialReportRecord
	record.Generation = uint64(row.Generation)
	record.State = domain.CredentialReportState(row.State)
	record.RequestedAt = row.RequestedAt
	record.GeneratedAt = row.GeneratedAt
	record.Content = row.Content
	return record, nil
}

func (w writer) PutCredentialReport(scope domain.Scope, record domain.CredentialReportRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteCredentialReport(w.ctx, sqlcgen.DeleteCredentialReportParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if err := w.q.InsertCredentialReport(w.ctx, sqlcgen.InsertCredentialReportParams{Partition: scope.Partition, Account: scope.AccountID, Generation: sqlite.Uint64(record.Generation), State: string(record.State), RequestedAt: record.RequestedAt, GeneratedAt: record.GeneratedAt, Content: record.Content}); err != nil {
		return err
	}
	return nil
}
