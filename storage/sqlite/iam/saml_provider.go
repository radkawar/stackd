package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) SAMLProvider(scope domain.Scope, key string) (domain.SAMLProviderRecord, error) {
	var result domain.SAMLProviderRecord
	row, err := r.q.GetSAMLProvider(r.ctx, sqlcgen.GetSAMLProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.SAMLProviderRecord
	record.ARN = row.Arn
	record.Name = row.Name
	record.UUID = row.Uuid
	record.MetadataDocument = row.MetadataDocument
	record.AssertionEncryptionMode = row.AssertionEncryptionMode
	record.CreatedAt = row.CreatedAt
	record.ValidUntil = row.ValidUntil
	{
		child, err := r.readSAMLProviderIssuers(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Issuers = child
	}
	{
		child, err := r.readSAMLProviderPrivateKeys(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.PrivateKeys = child
	}
	{
		child, err := r.readSAMLProviderTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	return record, nil
}

func (r reader) SAMLProviders(scope domain.Scope) ([]domain.SAMLProviderRecord, error) {
	rows, err := r.q.ListSAMLProviderKeys(r.ctx, sqlcgen.ListSAMLProviderKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.SAMLProviderRecord
	for _, row := range rows {
		record, err := r.SAMLProvider(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutSAMLProvider(scope domain.Scope, record domain.SAMLProviderRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteSAMLProvider(w.ctx, sqlcgen.DeleteSAMLProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ARN}); err != nil {
		return err
	}
	if err := w.q.InsertSAMLProvider(w.ctx, sqlcgen.InsertSAMLProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ARN, Arn: record.ARN, Name: record.Name, Uuid: record.UUID, MetadataDocument: record.MetadataDocument, AssertionEncryptionMode: record.AssertionEncryptionMode, CreatedAt: record.CreatedAt, ValidUntil: record.ValidUntil}); err != nil {
		return err
	}
	if err := w.writeSAMLProviderIssuers(scope.Partition, scope.AccountID, record.ARN, record.Issuers); err != nil {
		return err
	}
	if err := w.writeSAMLProviderPrivateKeys(scope.Partition, scope.AccountID, record.ARN, record.PrivateKeys); err != nil {
		return err
	}
	if err := w.writeSAMLProviderTags(scope.Partition, scope.AccountID, record.ARN, record.Tags); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteSAMLProvider(scope domain.Scope, key string) error {
	count, err := w.q.DeleteSAMLProvider(w.ctx, sqlcgen.DeleteSAMLProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readSAMLProviderIssuers(partition string, account string, resourceKey string) ([]domain.SAMLIssuerRecord, error) {
	var result []domain.SAMLIssuerRecord
	rows, err := r.q.ListSAMLProviderIssuers(r.ctx, sqlcgen.ListSAMLProviderIssuersParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.SAMLIssuerRecord
		record.EntityID = row.EntityID
		{
			child, err := r.readSAMLProviderIssuersSigningCertificates(row.Partition, row.Account, row.ResourceKey, row.Position1)
			if err != nil {
				return result, err
			}
			record.SigningCertificates = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readSAMLProviderIssuersSigningCertificates(partition string, account string, resourceKey string, position1 int64) ([][]byte, error) {
	var result [][]byte
	rows, err := r.q.ListSAMLProviderIssuersSigningCertificates(r.ctx, sqlcgen.ListSAMLProviderIssuersSigningCertificatesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readSAMLProviderPrivateKeys(partition string, account string, resourceKey string) ([]domain.SAMLPrivateKeyRecord, error) {
	var result []domain.SAMLPrivateKeyRecord
	rows, err := r.q.ListSAMLProviderPrivateKeys(r.ctx, sqlcgen.ListSAMLProviderPrivateKeysParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.SAMLPrivateKeyRecord
		record.ID = row.ID
		record.CreatedAt = row.CreatedAt
		record.PKCS8DER = row.Pkcs8Der
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readSAMLProviderTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListSAMLProviderTags(r.ctx, sqlcgen.ListSAMLProviderTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (w writer) writeSAMLProviderIssuers(partition string, account string, resourceKey string, value []domain.SAMLIssuerRecord) error {
	for position1, record := range value {
		if err := w.q.InsertSAMLProviderIssuers(w.ctx, sqlcgen.InsertSAMLProviderIssuersParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), EntityID: record.EntityID}); err != nil {
			return err
		}
		if err := w.writeSAMLProviderIssuersSigningCertificates(partition, account, resourceKey, int64(position1), record.SigningCertificates); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeSAMLProviderIssuersSigningCertificates(partition string, account string, resourceKey string, position1 int64, value [][]byte) error {
	for position2, record := range value {
		if err := w.q.InsertSAMLProviderIssuersSigningCertificates(w.ctx, sqlcgen.InsertSAMLProviderIssuersSigningCertificatesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: int64(position2), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeSAMLProviderPrivateKeys(partition string, account string, resourceKey string, value []domain.SAMLPrivateKeyRecord) error {
	for position1, record := range value {
		if err := w.q.InsertSAMLProviderPrivateKeys(w.ctx, sqlcgen.InsertSAMLProviderPrivateKeysParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), ID: record.ID, CreatedAt: record.CreatedAt, Pkcs8Der: record.PKCS8DER}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeSAMLProviderTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertSAMLProviderTags(w.ctx, sqlcgen.InsertSAMLProviderTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}
