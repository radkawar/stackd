package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) SigningCertificate(scope domain.Scope, key string) (domain.SigningCertificateRecord, error) {
	var result domain.SigningCertificateRecord
	row, err := r.q.GetSigningCertificate(r.ctx, sqlcgen.GetSigningCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.SigningCertificateRecord
	record.ID = row.ID
	record.UserID = row.UserID
	record.Body = row.Body
	record.Status = row.Status
	record.DER = row.Der
	record.UploadDate = row.UploadDate
	return record, nil
}

func (r reader) SigningCertificates(scope domain.Scope) ([]domain.SigningCertificateRecord, error) {
	rows, err := r.q.ListSigningCertificateKeys(r.ctx, sqlcgen.ListSigningCertificateKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.SigningCertificateRecord
	for _, row := range rows {
		record, err := r.SigningCertificate(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutSigningCertificate(scope domain.Scope, record domain.SigningCertificateRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteSigningCertificate(w.ctx, sqlcgen.DeleteSigningCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID}); err != nil {
		return err
	}
	if err := w.q.InsertSigningCertificate(w.ctx, sqlcgen.InsertSigningCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID, ID: record.ID, UserID: record.UserID, Body: record.Body, Status: record.Status, Der: record.DER, UploadDate: record.UploadDate}); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteSigningCertificate(scope domain.Scope, key string) error {
	count, err := w.q.DeleteSigningCertificate(w.ctx, sqlcgen.DeleteSigningCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}
