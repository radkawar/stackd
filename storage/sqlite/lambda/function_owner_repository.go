package lambda

import (
	"database/sql"
	"errors"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) functionOwner(k domain.FunctionKey, pending bool, version uint64) (domain.FunctionOwner, error) {
	row, err := r.q.GetFunctionOwner(r.ctx, sqlcgen.GetFunctionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionOwner{}, nil
	}
	if err != nil {
		return domain.FunctionOwner{}, err
	}
	return domain.FunctionOwner{StackID: row.StackID, LogicalID: row.LogicalID, Token: row.Token}, nil
}
func (w writer) putFunctionOwner(v domain.FunctionRecord, pending bool) error {
	k := v.Key
	if v.Owner == (domain.FunctionOwner{}) {
		return w.q.DeleteFunctionOwner(w.ctx, sqlcgen.DeleteFunctionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version)})
	}
	return w.q.PutFunctionOwner(w.ctx, sqlcgen.PutFunctionOwnerParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Pending: pending, Version: int64(v.Version), StackID: v.Owner.StackID, LogicalID: v.Owner.LogicalID, Token: v.Owner.Token})
}
