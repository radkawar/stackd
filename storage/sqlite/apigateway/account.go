package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) Account(scope domain.Scope) (domain.AccountRecord, error) {
	row, err := r.q.GetAccount(r.ctx, sqlcgen.GetAccountParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.AccountRecord{}, missing(err)
	}
	return domain.AccountRecord{Ownership: domain.Ownership{StackID: row.CfnStackID, LogicalID: row.CfnLogicalID, Incarnation: row.CfnIncarnation}, Scope: scope, CloudWatchRoleARN: row.CloudwatchRoleArn}, nil
}

func (w writer) PutAccount(row domain.AccountRecord) error {
	return w.q.PutAccount(w.ctx, sqlcgen.PutAccountParams{CfnStackID: row.Ownership.StackID, CfnLogicalID: row.Ownership.LogicalID, CfnIncarnation: row.Ownership.Incarnation, Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, CloudwatchRoleArn: row.CloudWatchRoleARN})
}
