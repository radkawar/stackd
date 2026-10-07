package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) OIDCProvider(scope domain.Scope, key string) (domain.OIDCProviderRecord, error) {
	var result domain.OIDCProviderRecord
	row, err := r.q.GetOIDCProvider(r.ctx, sqlcgen.GetOIDCProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.OIDCProviderRecord
	record.CloudFormationOwner = row.CfnOwner
	record.ARN = row.Arn
	record.ID = row.ID
	record.URL = row.Url
	record.CreatedAt = row.CreatedAt
	{
		child, err := r.readOIDCProviderClientIDs(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.ClientIDs = child
	}
	{
		child, err := r.readOIDCProviderThumbprints(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Thumbprints = child
	}
	{
		child, err := r.readOIDCProviderTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	return record, nil
}

func (r reader) OIDCProviders(scope domain.Scope) ([]domain.OIDCProviderRecord, error) {
	rows, err := r.q.ListOIDCProviderKeys(r.ctx, sqlcgen.ListOIDCProviderKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.OIDCProviderRecord
	for _, row := range rows {
		record, err := r.OIDCProvider(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutOIDCProvider(scope domain.Scope, record domain.OIDCProviderRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteOIDCProvider(w.ctx, sqlcgen.DeleteOIDCProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ARN}); err != nil {
		return err
	}
	if err := w.q.InsertOIDCProvider(w.ctx, sqlcgen.InsertOIDCProviderParams{CfnOwner: record.CloudFormationOwner, Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ARN, Arn: record.ARN, ID: record.ID, Url: record.URL, CreatedAt: record.CreatedAt}); err != nil {
		return err
	}
	if err := w.writeOIDCProviderClientIDs(scope.Partition, scope.AccountID, record.ARN, record.ClientIDs); err != nil {
		return err
	}
	if err := w.writeOIDCProviderThumbprints(scope.Partition, scope.AccountID, record.ARN, record.Thumbprints); err != nil {
		return err
	}
	if err := w.writeOIDCProviderTags(scope.Partition, scope.AccountID, record.ARN, record.Tags); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteOIDCProvider(scope domain.Scope, key string) error {
	count, err := w.q.DeleteOIDCProvider(w.ctx, sqlcgen.DeleteOIDCProviderParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readOIDCProviderClientIDs(partition string, account string, resourceKey string) ([]string, error) {
	var result []string
	rows, err := r.q.ListOIDCProviderClientIDs(r.ctx, sqlcgen.ListOIDCProviderClientIDsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readOIDCProviderThumbprints(partition string, account string, resourceKey string) ([]string, error) {
	var result []string
	rows, err := r.q.ListOIDCProviderThumbprints(r.ctx, sqlcgen.ListOIDCProviderThumbprintsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readOIDCProviderTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListOIDCProviderTags(r.ctx, sqlcgen.ListOIDCProviderTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (w writer) writeOIDCProviderClientIDs(partition string, account string, resourceKey string, value []string) error {
	for position1, record := range value {
		if err := w.q.InsertOIDCProviderClientIDs(w.ctx, sqlcgen.InsertOIDCProviderClientIDsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeOIDCProviderThumbprints(partition string, account string, resourceKey string, value []string) error {
	for position1, record := range value {
		if err := w.q.InsertOIDCProviderThumbprints(w.ctx, sqlcgen.InsertOIDCProviderThumbprintsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeOIDCProviderTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertOIDCProviderTags(w.ctx, sqlcgen.InsertOIDCProviderTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}
