package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) RecursiveLoop(key domain.FunctionKey) (string, error) {
	mode, err := r.q.GetRecursiveLoop(r.ctx, sqlcgen.GetRecursiveLoopParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return "Terminate", nil
	}
	return mode, err
}
func (w writer) PutRecursiveLoop(key domain.FunctionKey, mode string) error {
	return w.q.PutRecursiveLoop(w.ctx, sqlcgen.PutRecursiveLoopParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, RecursiveLoop: mode})
}
func (r reader) RuntimeManagement(key domain.FunctionVersionKey) (string, error) {
	mode, err := r.q.GetRuntimeManagement(r.ctx, sqlcgen.GetRuntimeManagementParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Version: int64(key.Version)})
	if errors.Is(err, sql.ErrNoRows) {
		return "Auto", nil
	}
	return mode, err
}
func (w writer) PutRuntimeManagement(key domain.FunctionVersionKey, mode string) error {
	return w.q.PutRuntimeManagement(w.ctx, sqlcgen.PutRuntimeManagementParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Version: int64(key.Version), UpdateRuntimeOn: mode})
}
func (w writer) DeleteRuntimeManagement(key domain.FunctionVersionKey) error {
	return w.q.DeleteRuntimeManagement(w.ctx, sqlcgen.DeleteRuntimeManagementParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Version: int64(key.Version)})
}
func provisionedRecord(row sqlcgen.LambdaProvisionedConcurrency) domain.ProvisionedConcurrencyRecord {
	return domain.ProvisionedConcurrencyRecord{Key: domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: row.Partition, Account: row.Account, Region: row.Region}, Name: row.FunctionName}, Qualifier: row.Qualifier}, Requested: int32(row.Requested), Generation: row.Generation, Status: row.Status, StatusReason: row.StatusReason, Modified: row.Modified}
}
func (r reader) ProvisionedConcurrency(key domain.FunctionReference) (domain.ProvisionedConcurrencyRecord, error) {
	row, err := r.q.GetProvisionedConcurrency(r.ctx, sqlcgen.GetProvisionedConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ProvisionedConcurrencyRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ProvisionedConcurrencyRecord{}, err
	}
	return provisionedRecord(row), nil
}
func (r reader) AllProvisionedConcurrency() ([]domain.ProvisionedConcurrencyRecord, error) {
	rows, err := r.q.ListProvisionedConcurrency(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ProvisionedConcurrencyRecord, len(rows))
	for i, row := range rows {
		out[i] = provisionedRecord(row)
	}
	return out, nil
}
func (w writer) PutProvisionedConcurrency(row domain.ProvisionedConcurrencyRecord) error {
	key := row.Key
	return w.q.PutProvisionedConcurrency(w.ctx, sqlcgen.PutProvisionedConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier, Requested: int64(row.Requested), Generation: row.Generation, Status: row.Status, StatusReason: row.StatusReason, Modified: row.Modified})
}
func (w writer) DeleteProvisionedConcurrency(key domain.FunctionReference) error {
	return w.q.DeleteProvisionedConcurrency(w.ctx, sqlcgen.DeleteProvisionedConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Qualifier: key.Qualifier})
}
