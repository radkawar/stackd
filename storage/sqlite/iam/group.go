package iam

import (
	"database/sql"
	"errors"
	"strings"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) Group(scope domain.Scope, key string) (domain.Group, error) {
	var result domain.Group
	row, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.Group
	record.Path = row.Path
	record.GroupName = row.GroupName
	record.GroupId = row.GroupID
	record.Arn = row.Arn
	record.CreateDate = row.CreateDate
	{
		child, err := r.readGroupInline(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Inline = child
	}
	{
		child, err := r.readGroupAttached(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Attached = child
	}
	{
		child, err := r.readGroupMembers(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Members = child
	}
	return record, nil
}

func (r reader) Groups(scope domain.Scope) ([]domain.Group, error) {
	rows, err := r.q.ListGroupKeys(r.ctx, sqlcgen.ListGroupKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.Group
	for _, row := range rows {
		record, err := r.Group(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutGroup(scope domain.Scope, record domain.Group) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.GroupName)}); err != nil {
		return err
	}
	if err := w.q.InsertGroup(w.ctx, sqlcgen.InsertGroupParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.GroupName), Path: record.Path, GroupName: record.GroupName, GroupID: record.GroupId, Arn: record.Arn, CreateDate: record.CreateDate}); err != nil {
		return err
	}
	if err := w.writeGroupInline(scope.Partition, scope.AccountID, strings.ToLower(record.GroupName), record.Inline); err != nil {
		return err
	}
	if err := w.writeGroupAttached(scope.Partition, scope.AccountID, strings.ToLower(record.GroupName), record.Attached); err != nil {
		return err
	}
	if err := w.writeGroupMembers(scope.Partition, scope.AccountID, strings.ToLower(record.GroupName), record.Members); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteGroup(scope domain.Scope, key string) error {
	count, err := w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readGroupInline(partition string, account string, resourceKey string) (map[string]string, error) {
	var result map[string]string
	rows, err := r.q.ListGroupInline(r.ctx, sqlcgen.ListGroupInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]string, len(rows))
	for _, row := range rows {
		record := row.Value
		result[row.Entry1] = record
	}
	return result, nil
}

func (r reader) readGroupAttached(partition string, account string, resourceKey string) (map[string]struct{}, error) {
	var result map[string]struct{}
	rows, err := r.q.ListGroupAttached(r.ctx, sqlcgen.ListGroupAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]struct{}, len(rows))
	for _, row := range rows {
		result[row.Entry1] = struct{}{}
	}
	return result, nil
}

func (r reader) readGroupMembers(partition string, account string, resourceKey string) (map[string]struct{}, error) {
	var result map[string]struct{}
	rows, err := r.q.ListGroupMembers(r.ctx, sqlcgen.ListGroupMembersParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]struct{}, len(rows))
	for _, row := range rows {
		result[row.Entry1] = struct{}{}
	}
	return result, nil
}

func (w writer) writeGroupInline(partition string, account string, resourceKey string, value map[string]string) error {
	for entry1, record := range value {
		if err := w.q.InsertGroupInline(w.ctx, sqlcgen.InsertGroupInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeGroupAttached(partition string, account string, resourceKey string, value map[string]struct{}) error {
	for entry1 := range value {
		if err := w.q.InsertGroupAttached(w.ctx, sqlcgen.InsertGroupAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeGroupMembers(partition string, account string, resourceKey string, value map[string]struct{}) error {
	for entry1 := range value {
		if err := w.q.InsertGroupMembers(w.ctx, sqlcgen.InsertGroupMembersParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1}); err != nil {
			return err
		}
	}
	return nil
}
