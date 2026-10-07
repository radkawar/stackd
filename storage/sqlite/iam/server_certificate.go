package iam

import (
	"database/sql"
	"errors"
	"strings"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) ServerCertificate(scope domain.Scope, key string) (domain.ServerCertificateRecord, error) {
	var result domain.ServerCertificateRecord
	row, err := r.q.GetServerCertificate(r.ctx, sqlcgen.GetServerCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.ServerCertificateRecord
	record.CloudFormationOwner = row.CfnOwner
	record.ID = row.ID
	record.Name = row.Name
	record.Path = row.Path
	record.ARN = row.Arn
	record.Body = row.Body
	record.Chain = row.Chain
	record.PrivateKey = row.PrivateKey
	record.UploadDate = row.UploadDate
	record.Expiration = row.Expiration
	record.TaggingInvalid = row.TaggingInvalid
	{
		child, err := r.readServerCertificateTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	return record, nil
}

func (r reader) ServerCertificates(scope domain.Scope) ([]domain.ServerCertificateRecord, error) {
	rows, err := r.q.ListServerCertificateKeys(r.ctx, sqlcgen.ListServerCertificateKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.ServerCertificateRecord
	for _, row := range rows {
		record, err := r.ServerCertificate(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutServerCertificate(scope domain.Scope, record domain.ServerCertificateRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteServerCertificate(w.ctx, sqlcgen.DeleteServerCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.Name)}); err != nil {
		return err
	}
	if err := w.q.InsertServerCertificate(w.ctx, sqlcgen.InsertServerCertificateParams{CfnOwner: record.CloudFormationOwner, Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.Name), ID: record.ID, Name: record.Name, Path: record.Path, Arn: record.ARN, Body: record.Body, Chain: record.Chain, PrivateKey: record.PrivateKey, UploadDate: record.UploadDate, Expiration: record.Expiration, TaggingInvalid: record.TaggingInvalid}); err != nil {
		return err
	}
	if err := w.writeServerCertificateTags(scope.Partition, scope.AccountID, strings.ToLower(record.Name), record.Tags); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteServerCertificate(scope domain.Scope, key string) error {
	count, err := w.q.DeleteServerCertificate(w.ctx, sqlcgen.DeleteServerCertificateParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readServerCertificateTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListServerCertificateTags(r.ctx, sqlcgen.ListServerCertificateTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.Tag
		record.Key = row.Key
		record.Value = row.Value
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeServerCertificateTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertServerCertificateTags(w.ctx, sqlcgen.InsertServerCertificateTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}
