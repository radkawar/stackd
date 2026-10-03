package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) ServiceCredential(scope domain.Scope, key string) (domain.ServiceCredentialRecord, error) {
	var result domain.ServiceCredentialRecord
	row, err := r.q.GetServiceCredential(r.ctx, sqlcgen.GetServiceCredentialParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.ServiceCredentialRecord
	record.ID = row.ID
	record.UserID = row.UserID
	record.ServiceName = row.ServiceName
	record.ServiceUserName = row.ServiceUserName
	record.ServiceCredentialAlias = row.ServiceCredentialAlias
	record.Status = row.Status
	record.CreateDate = row.CreateDate
	record.ExpirationDate = row.ExpirationDate
	record.CredentialAgeDays = row.CredentialAgeDays
	copy(record.SecretDigest[:], row.SecretDigest)
	record.Slot = int(row.Slot)
	return record, nil
}

func (r reader) ServiceCredentials(scope domain.Scope) ([]domain.ServiceCredentialRecord, error) {
	rows, err := r.q.ListServiceCredentialKeys(r.ctx, sqlcgen.ListServiceCredentialKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.ServiceCredentialRecord
	for _, row := range rows {
		record, err := r.ServiceCredential(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutServiceCredential(scope domain.Scope, record domain.ServiceCredentialRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteServiceCredential(w.ctx, sqlcgen.DeleteServiceCredentialParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID}); err != nil {
		return err
	}
	if err := w.q.InsertServiceCredential(w.ctx, sqlcgen.InsertServiceCredentialParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID, ID: record.ID, UserID: record.UserID, ServiceName: record.ServiceName, ServiceUserName: record.ServiceUserName, ServiceCredentialAlias: record.ServiceCredentialAlias, Status: record.Status, CreateDate: record.CreateDate, ExpirationDate: record.ExpirationDate, CredentialAgeDays: record.CredentialAgeDays, SecretDigest: record.SecretDigest[:], Slot: int64(record.Slot)}); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteServiceCredential(scope domain.Scope, key string) error {
	count, err := w.q.DeleteServiceCredential(w.ctx, sqlcgen.DeleteServiceCredentialParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}
