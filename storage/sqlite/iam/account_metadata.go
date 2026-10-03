package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) AccountMetadata(scope domain.Scope) (domain.AccountMetadata, error) {
	var result domain.AccountMetadata
	row, err := r.q.GetAccountMetadata(r.ctx, sqlcgen.GetAccountMetadataParams{Partition: scope.Partition, Account: scope.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.AccountMetadata
	record.CreatedAt = row.CreatedAt
	return record, nil
}

func (w writer) PutAccountMetadata(scope domain.Scope, record domain.AccountMetadata) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteAccountMetadata(w.ctx, sqlcgen.DeleteAccountMetadataParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if err := w.q.InsertAccountMetadata(w.ctx, sqlcgen.InsertAccountMetadataParams{Partition: scope.Partition, Account: scope.AccountID, CreatedAt: record.CreatedAt}); err != nil {
		return err
	}
	return nil
}
