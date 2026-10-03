package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) Account(scope domain.Scope) (domain.AccountRecord, error) {
	role, err := r.q.GetAccount(r.ctx, sqlcgen.GetAccountParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.AccountRecord{}, missing(err)
	}
	return domain.AccountRecord{Scope: scope, CloudWatchRoleARN: role}, nil
}

func (w writer) PutAccount(row domain.AccountRecord) error {
	return w.q.PutAccount(w.ctx, sqlcgen.PutAccountParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, CloudwatchRoleArn: row.CloudWatchRoleARN})
}
