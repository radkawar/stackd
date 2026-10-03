package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) ServiceLinkedRoleDeletion(scope domain.Scope, key string) (domain.ServiceLinkedRoleDeletion, error) {
	var result domain.ServiceLinkedRoleDeletion
	row, err := r.q.GetServiceLinkedRoleDeletion(r.ctx, sqlcgen.GetServiceLinkedRoleDeletionParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.ServiceLinkedRoleDeletion
	record.ID = row.ID
	record.RoleID = row.RoleID
	record.RoleARN = row.RoleArn
	record.RoleName = row.RoleName
	record.ServiceName = row.ServiceName
	record.Status = row.Status
	record.FailureReason = row.FailureReason
	record.CreatedAt = row.CreatedAt
	record.UpdatedAt = row.UpdatedAt
	{
		child, err := r.readServiceLinkedRoleDeletionUsage(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Usage = child
	}
	return record, nil
}

func (r reader) ServiceLinkedRoleDeletions(scope domain.Scope) ([]domain.ServiceLinkedRoleDeletion, error) {
	rows, err := r.q.ListServiceLinkedRoleDeletionKeys(r.ctx, sqlcgen.ListServiceLinkedRoleDeletionKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.ServiceLinkedRoleDeletion
	for _, row := range rows {
		record, err := r.ServiceLinkedRoleDeletion(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutServiceLinkedRoleDeletion(scope domain.Scope, record domain.ServiceLinkedRoleDeletion) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteServiceLinkedRoleDeletion(w.ctx, sqlcgen.DeleteServiceLinkedRoleDeletionParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID}); err != nil {
		return err
	}
	if err := w.q.InsertServiceLinkedRoleDeletion(w.ctx, sqlcgen.InsertServiceLinkedRoleDeletionParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID, ID: record.ID, RoleID: record.RoleID, RoleArn: record.RoleARN, RoleName: record.RoleName, ServiceName: record.ServiceName, Status: record.Status, FailureReason: record.FailureReason, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}); err != nil {
		return err
	}
	if err := w.writeServiceLinkedRoleDeletionUsage(scope.Partition, scope.AccountID, record.ID, record.Usage); err != nil {
		return err
	}
	return nil
}

func (r reader) readServiceLinkedRoleDeletionUsage(partition string, account string, resourceKey string) ([]domain.ServiceLinkedRoleUsage, error) {
	var result []domain.ServiceLinkedRoleUsage
	rows, err := r.q.ListServiceLinkedRoleDeletionUsage(r.ctx, sqlcgen.ListServiceLinkedRoleDeletionUsageParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.ServiceLinkedRoleUsage
		record.Region = row.Region
		{
			child, err := r.readServiceLinkedRoleDeletionUsageResourceARNs(row.Partition, row.Account, row.ResourceKey, row.Position1)
			if err != nil {
				return result, err
			}
			record.ResourceARNs = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readServiceLinkedRoleDeletionUsageResourceARNs(partition string, account string, resourceKey string, position1 int64) ([]string, error) {
	var result []string
	rows, err := r.q.ListServiceLinkedRoleDeletionUsageResourceARNs(r.ctx, sqlcgen.ListServiceLinkedRoleDeletionUsageResourceARNsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeServiceLinkedRoleDeletionUsage(partition string, account string, resourceKey string, value []domain.ServiceLinkedRoleUsage) error {
	for position1, record := range value {
		if err := w.q.InsertServiceLinkedRoleDeletionUsage(w.ctx, sqlcgen.InsertServiceLinkedRoleDeletionUsageParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Region: record.Region}); err != nil {
			return err
		}
		if err := w.writeServiceLinkedRoleDeletionUsageResourceARNs(partition, account, resourceKey, int64(position1), record.ResourceARNs); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeServiceLinkedRoleDeletionUsageResourceARNs(partition string, account string, resourceKey string, position1 int64, value []string) error {
	for position2, record := range value {
		if err := w.q.InsertServiceLinkedRoleDeletionUsageResourceARNs(w.ctx, sqlcgen.InsertServiceLinkedRoleDeletionUsageResourceARNsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: int64(position2), Value: record}); err != nil {
			return err
		}
	}
	return nil
}
