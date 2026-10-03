package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) SSHPublicKey(scope domain.Scope, key string) (domain.SSHPublicKeyRecord, error) {
	var result domain.SSHPublicKeyRecord
	row, err := r.q.GetSSHPublicKey(r.ctx, sqlcgen.GetSSHPublicKeyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.SSHPublicKeyRecord
	record.ID = row.ID
	record.UserID = row.UserID
	record.Body = row.Body
	record.Fingerprint = row.Fingerprint
	record.Status = row.Status
	record.Wire = row.Wire
	record.UploadDate = row.UploadDate
	return record, nil
}

func (r reader) SSHPublicKeys(scope domain.Scope) ([]domain.SSHPublicKeyRecord, error) {
	rows, err := r.q.ListSSHPublicKeyKeys(r.ctx, sqlcgen.ListSSHPublicKeyKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.SSHPublicKeyRecord
	for _, row := range rows {
		record, err := r.SSHPublicKey(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutSSHPublicKey(scope domain.Scope, record domain.SSHPublicKeyRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteSSHPublicKey(w.ctx, sqlcgen.DeleteSSHPublicKeyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID}); err != nil {
		return err
	}
	if err := w.q.InsertSSHPublicKey(w.ctx, sqlcgen.InsertSSHPublicKeyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID, ID: record.ID, UserID: record.UserID, Body: record.Body, Fingerprint: record.Fingerprint, Status: record.Status, Wire: record.Wire, UploadDate: record.UploadDate}); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteSSHPublicKey(scope domain.Scope, key string) error {
	count, err := w.q.DeleteSSHPublicKey(w.ctx, sqlcgen.DeleteSSHPublicKeyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}
