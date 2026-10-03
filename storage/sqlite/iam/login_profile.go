package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) LoginProfile(scope domain.Scope, key string) (domain.LoginProfileRecord, error) {
	var result domain.LoginProfileRecord
	row, err := r.q.GetLoginProfile(r.ctx, sqlcgen.GetLoginProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.LoginProfileRecord
	record.UserID = row.UserID
	record.CreateDate = row.CreateDate
	record.PasswordChangedAt = row.PasswordChangedAt
	record.PasswordResetRequired = row.PasswordResetRequired
	record.Password.Algorithm = row.PasswordAlgorithm
	record.Password.Iterations = int(row.PasswordIterations)
	record.Password.Salt = row.PasswordSalt
	record.Password.Hash = row.PasswordHash
	{
		child, err := r.readLoginProfilePreviousPasswords(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.PreviousPasswords = child
	}
	return record, nil
}

func (r reader) LoginProfiles(scope domain.Scope) ([]domain.LoginProfileRecord, error) {
	rows, err := r.q.ListLoginProfileKeys(r.ctx, sqlcgen.ListLoginProfileKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.LoginProfileRecord
	for _, row := range rows {
		record, err := r.LoginProfile(scope, row.ResourceKey)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutLoginProfile(scope domain.Scope, record domain.LoginProfileRecord) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteLoginProfile(w.ctx, sqlcgen.DeleteLoginProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.UserID}); err != nil {
		return err
	}
	if err := w.q.InsertLoginProfile(w.ctx, sqlcgen.InsertLoginProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.UserID, UserID: record.UserID, CreateDate: record.CreateDate, PasswordChangedAt: record.PasswordChangedAt, PasswordResetRequired: record.PasswordResetRequired, PasswordAlgorithm: record.Password.Algorithm, PasswordIterations: int64(record.Password.Iterations), PasswordSalt: record.Password.Salt, PasswordHash: record.Password.Hash}); err != nil {
		return err
	}
	if err := w.writeLoginProfilePreviousPasswords(scope.Partition, scope.AccountID, record.UserID, record.PreviousPasswords); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteLoginProfile(scope domain.Scope, key string) error {
	count, err := w.q.DeleteLoginProfile(w.ctx, sqlcgen.DeleteLoginProfileParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrRecordNotFound
	}
	return nil
}

func (r reader) readLoginProfilePreviousPasswords(partition string, account string, resourceKey string) ([]domain.PasswordDigest, error) {
	var result []domain.PasswordDigest
	rows, err := r.q.ListLoginProfilePreviousPasswords(r.ctx, sqlcgen.ListLoginProfilePreviousPasswordsParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.PasswordDigest
		record.Algorithm = row.Algorithm
		record.Iterations = int(row.Iterations)
		record.Salt = row.Salt
		record.Hash = row.Hash
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeLoginProfilePreviousPasswords(partition string, account string, resourceKey string, value []domain.PasswordDigest) error {
	for position1, record := range value {
		if err := w.q.InsertLoginProfilePreviousPasswords(w.ctx, sqlcgen.InsertLoginProfilePreviousPasswordsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Algorithm: record.Algorithm, Iterations: int64(record.Iterations), Salt: record.Salt, Hash: record.Hash}); err != nil {
			return err
		}
	}
	return nil
}
