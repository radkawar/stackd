package iam

import (
	"database/sql"
	"errors"
	"strings"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) InstanceProfile(scope domain.Scope, key string) (domain.InstanceProfile, error) {
	var result domain.InstanceProfile
	row, err := r.q.GetInstanceProfile(r.ctx, sqlcgen.GetInstanceProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.InstanceProfile
	record.Path = row.Path
	record.CloudFormationOwner = row.CfnOwner
	record.InstanceProfileName = row.InstanceProfileName
	record.InstanceProfileId = row.InstanceProfileID
	record.Arn = row.Arn
	record.RoleId = row.RoleID
	record.CreateDate = row.CreateDate
	{
		child, err := r.readInstanceProfileTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	return record, nil
}

func (r reader) InstanceProfiles(scope domain.Scope) ([]domain.InstanceProfile, error) {
	rows, err := r.q.ListInstanceProfileKeys(r.ctx, sqlcgen.ListInstanceProfileKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.InstanceProfile
	for _, row := range rows {
		record, err := r.InstanceProfile(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutInstanceProfile(scope domain.Scope, record domain.InstanceProfile) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteInstanceProfile(w.ctx, sqlcgen.DeleteInstanceProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.InstanceProfileName)}); err != nil {
		return err
	}
	if err := w.q.InsertInstanceProfile(w.ctx, sqlcgen.InsertInstanceProfileParams{CfnOwner: record.CloudFormationOwner, Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.InstanceProfileName), Path: record.Path, InstanceProfileName: record.InstanceProfileName, InstanceProfileID: record.InstanceProfileId, Arn: record.Arn, RoleID: record.RoleId, CreateDate: record.CreateDate}); err != nil {
		return err
	}
	if err := w.writeInstanceProfileTags(scope.Partition, scope.AccountID, strings.ToLower(record.InstanceProfileName), record.Tags); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteInstanceProfile(scope domain.Scope, key string) error {
	count, err := w.q.DeleteInstanceProfile(w.ctx, sqlcgen.DeleteInstanceProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readInstanceProfileTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListInstanceProfileTags(r.ctx, sqlcgen.ListInstanceProfileTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (w writer) writeInstanceProfileTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertInstanceProfileTags(w.ctx, sqlcgen.InsertInstanceProfileTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}
