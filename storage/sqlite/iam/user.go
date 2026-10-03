package iam

import (
	"database/sql"
	"errors"
	"strings"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) User(scope domain.Scope, key string) (domain.User, error) {
	var result domain.User
	row, err := r.q.GetUser(r.ctx, sqlcgen.GetUserParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.User
	record.Path = row.Path
	record.UserName = row.UserName
	record.UserId = row.UserID
	record.Arn = row.Arn
	record.CreateDate = row.CreateDate
	record.PasswordLastUsed = row.PasswordLastUsed
	{
		child, err := r.readUserPermissionsBoundary(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.PermissionsBoundary = child
	}
	{
		child, err := r.readUserTags(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Tags = child
	}
	{
		child, err := r.readUserInline(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Inline = child
	}
	{
		child, err := r.readUserAttached(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Attached = child
	}
	return record, nil
}

func (r reader) Users(scope domain.Scope) ([]domain.User, error) {
	rows, err := r.q.ListUserKeys(r.ctx, sqlcgen.ListUserKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.User
	for _, row := range rows {
		record, err := r.User(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutUser(scope domain.Scope, record domain.User) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteUser(w.ctx, sqlcgen.DeleteUserParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.UserName)}); err != nil {
		return err
	}
	if err := w.q.InsertUser(w.ctx, sqlcgen.InsertUserParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.UserName), Path: record.Path, UserName: record.UserName, UserID: record.UserId, Arn: record.Arn, CreateDate: record.CreateDate, PasswordLastUsed: record.PasswordLastUsed}); err != nil {
		return err
	}
	if err := w.writeUserPermissionsBoundary(scope.Partition, scope.AccountID, strings.ToLower(record.UserName), record.PermissionsBoundary); err != nil {
		return err
	}
	if err := w.writeUserTags(scope.Partition, scope.AccountID, strings.ToLower(record.UserName), record.Tags); err != nil {
		return err
	}
	if err := w.writeUserInline(scope.Partition, scope.AccountID, strings.ToLower(record.UserName), record.Inline); err != nil {
		return err
	}
	if err := w.writeUserAttached(scope.Partition, scope.AccountID, strings.ToLower(record.UserName), record.Attached); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteUser(scope domain.Scope, key string) error {
	count, err := w.q.DeleteUser(w.ctx, sqlcgen.DeleteUserParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readUserPermissionsBoundary(partition string, account string, resourceKey string) (*domain.Boundary, error) {
	var result *domain.Boundary
	row, err := r.q.GetUserPermissionsBoundary(r.ctx, sqlcgen.GetUserPermissionsBoundaryParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.Boundary{}
	record.PermissionsBoundaryType = row.PermissionsBoundaryType
	record.PermissionsBoundaryArn = row.PermissionsBoundaryArn
	return record, nil
}

func (r reader) readUserTags(partition string, account string, resourceKey string) ([]domain.Tag, error) {
	var result []domain.Tag
	rows, err := r.q.ListUserTags(r.ctx, sqlcgen.ListUserTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (r reader) readUserInline(partition string, account string, resourceKey string) (map[string]string, error) {
	var result map[string]string
	rows, err := r.q.ListUserInline(r.ctx, sqlcgen.ListUserInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey})
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

func (r reader) readUserAttached(partition string, account string, resourceKey string) (map[string]struct{}, error) {
	var result map[string]struct{}
	rows, err := r.q.ListUserAttached(r.ctx, sqlcgen.ListUserAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	result = make(map[string]struct{}, len(rows))
	for _, row := range rows {
		result[row.Entry1] = struct{}{}
	}
	return result, nil
}

func (w writer) writeUserPermissionsBoundary(partition string, account string, resourceKey string, record *domain.Boundary) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertUserPermissionsBoundary(w.ctx, sqlcgen.InsertUserPermissionsBoundaryParams{Partition: partition, Account: account, ResourceKey: resourceKey, PermissionsBoundaryType: record.PermissionsBoundaryType, PermissionsBoundaryArn: record.PermissionsBoundaryArn}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeUserTags(partition string, account string, resourceKey string, value []domain.Tag) error {
	for position1, record := range value {
		if err := w.q.InsertUserTags(w.ctx, sqlcgen.InsertUserTagsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Key: record.Key, Value: record.Value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeUserInline(partition string, account string, resourceKey string, value map[string]string) error {
	for entry1, record := range value {
		if err := w.q.InsertUserInline(w.ctx, sqlcgen.InsertUserInlineParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1, Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeUserAttached(partition string, account string, resourceKey string, value map[string]struct{}) error {
	for entry1 := range value {
		if err := w.q.InsertUserAttached(w.ctx, sqlcgen.InsertUserAttachedParams{Partition: partition, Account: account, ResourceKey: resourceKey, Entry1: entry1}); err != nil {
			return err
		}
	}
	return nil
}
