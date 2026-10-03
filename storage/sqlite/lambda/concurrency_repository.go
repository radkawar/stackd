package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) FunctionConcurrency(key domain.FunctionKey) (int32, bool, error) {
	reserved, err := r.q.GetFunctionConcurrency(r.ctx, sqlcgen.GetFunctionConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return int32(reserved), true, nil
}

func (r reader) AccountUsage(scope domain.Scope) (domain.AccountUsage, error) {
	row, err := r.q.GetAccountUsage(r.ctx, sqlcgen.GetAccountUsageParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return domain.AccountUsage{}, err
	}
	return domain.AccountUsage{FunctionCount: row.FunctionCount, TotalCodeSize: row.TotalCodeSize, ReservedConcurrency: row.ReservedConcurrency}, nil
}

func (w writer) PutFunctionConcurrency(key domain.FunctionKey, reserved int32) error {
	return w.q.PutFunctionConcurrency(w.ctx, sqlcgen.PutFunctionConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, ReservedConcurrency: int64(reserved)})
}

func (w writer) DeleteFunctionConcurrency(key domain.FunctionKey) error {
	return w.q.DeleteFunctionConcurrency(w.ctx, sqlcgen.DeleteFunctionConcurrencyParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name})
}
