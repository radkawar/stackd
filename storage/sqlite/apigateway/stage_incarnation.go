package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (w writer) NextStageIncarnation(scope domain.Scope) (uint64, error) {
	next, err := w.q.NextStageIncarnation(w.ctx, sqlcgen.NextStageIncarnationParams{
		Partition: scope.Partition,
		AccountID: scope.AccountID,
		Region:    scope.Region,
	})
	return uint64(next), err
}
