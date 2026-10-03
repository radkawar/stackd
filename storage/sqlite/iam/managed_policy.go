package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) ManagedPolicy(scope domain.Scope, key string) (domain.ManagedPolicy, error) {
	var result domain.ManagedPolicy
	row, err := r.q.GetManagedPolicy(r.ctx, sqlcgen.GetManagedPolicyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.ManagedPolicy
	record.PolicyName = row.PolicyName
	record.PolicyId = row.PolicyID
	record.Arn = row.Arn
	record.Path = row.Path
	record.DefaultVersionId = row.DefaultVersionID
	record.Description = row.Description
	record.AttachmentCount = int(row.AttachmentCount)
	record.PermissionsBoundaryUsageCount = int(row.PermissionsBoundaryUsageCount)
	record.NextVersion = int(row.NextVersion)
	record.IsAttachable = row.IsAttachable
	record.CreateDate = row.CreateDate
	record.UpdateDate = row.UpdateDate
	{
		child, err := r.readManagedPolicyTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	{
		child, err := r.readManagedPolicyVersions(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Versions = child
	}
	return record, nil
}

func (r reader) ManagedPolicies(scope domain.Scope) ([]domain.ManagedPolicy, error) {
	rows, err := r.q.ListManagedPolicyKeys(r.ctx, sqlcgen.ListManagedPolicyKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.ManagedPolicy
	for _, row := range rows {
		record, err := r.ManagedPolicy(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutManagedPolicy(scope domain.Scope, record domain.ManagedPolicy) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteManagedPolicy(w.ctx, sqlcgen.DeleteManagedPolicyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.Arn}); err != nil {
		return err
	}
	if err := w.q.InsertManagedPolicy(w.ctx, sqlcgen.InsertManagedPolicyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.Arn, PolicyName: record.PolicyName, PolicyID: record.PolicyId, Arn: record.Arn, Path: record.Path, DefaultVersionID: record.DefaultVersionId, Description: record.Description, AttachmentCount: int64(record.AttachmentCount), PermissionsBoundaryUsageCount: int64(record.PermissionsBoundaryUsageCount), NextVersion: int64(record.NextVersion), IsAttachable: record.IsAttachable, CreateDate: record.CreateDate, UpdateDate: record.UpdateDate}); err != nil {
		return err
	}
	if err := w.writeManagedPolicyTags(scope.Partition, scope.AccountID, record.Arn, record.Tags); err != nil {
		return err
	}
	if err := w.writeManagedPolicyVersions(scope.Partition, scope.AccountID, record.Arn, record.Versions); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteManagedPolicy(scope domain.Scope, key string) error {
	count, err := w.q.DeleteManagedPolicy(w.ctx, sqlcgen.DeleteManagedPolicyParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readManagedPolicyTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListManagedPolicyTags(r.ctx, sqlcgen.ListManagedPolicyTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (r reader) readManagedPolicyVersions(partition string, account string, resourceKey string) (map[string]*domain.PolicyVersion, error) {
	var result map[string]*domain.PolicyVersion
	rows, err := r.q.ListManagedPolicyVersions(r.ctx, sqlcgen.ListManagedPolicyVersionsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]*domain.PolicyVersion, len(rows))
	for _, row := range rows {
		record := &domain.PolicyVersion{}
		record.Document = row.Document
		record.VersionId = row.VersionID
		record.IsDefaultVersion = row.IsDefaultVersion
		record.CreateDate = row.CreateDate
		result[row.Entry1] = record
	}
	return result, nil
}

func (w writer) writeManagedPolicyTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertManagedPolicyTags(w.ctx, sqlcgen.InsertManagedPolicyTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeManagedPolicyVersions(partition string, account string, resourceKey string, value map[string]*domain.PolicyVersion) error {
	for entry1, record := range value {
		if err := w.q.InsertManagedPolicyVersions(w.ctx, sqlcgen.InsertManagedPolicyVersionsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, Document: record.Document, VersionID: record.VersionId, IsDefaultVersion: record.IsDefaultVersion, CreateDate: record.CreateDate}); err != nil {
			return err
		}
	}
	return nil
}
