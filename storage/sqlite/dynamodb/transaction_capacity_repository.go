package dynamodb

import (
	"time"

	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) TransactionCapacity(k domain.TransactionCapacityKey) (domain.TransactionCapacity, error) {
	recorded, err := r.q.GetTransactionCapacity(r.ctx, sqlcgen.GetTransactionCapacityParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: k.Token,
	})
	if err != nil {
		return domain.TransactionCapacity{}, missing(err)
	}
	rows, err := r.q.GetTransactionCapacityReads(r.ctx, sqlcgen.GetTransactionCapacityReadsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: k.Token,
	})
	if err != nil {
		return domain.TransactionCapacity{}, err
	}
	v := domain.TransactionCapacity{
		Key: k, ExpiresAt: recorded.ExpiresAt,
		ReturnConsumedCapacity:      recorded.ReturnConsumedCapacity,
		ReturnItemCollectionMetrics: recorded.ReturnItemCollectionMetrics,
		CanceledRequest:             recorded.CanceledRequest,
	}
	if len(rows) > 0 {
		v.Read = make([]domain.TransactionReadCapacity, len(rows))
		for i, row := range rows {
			v.Read[i] = domain.TransactionReadCapacity{TableName: row.TableName, Units: row.Units}
		}
	}
	return v, nil
}

func (w writer) PutTransactionCapacity(v domain.TransactionCapacity) error {
	k := v.Key
	if err := w.q.PutTransactionCapacity(w.ctx, sqlcgen.PutTransactionCapacityParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: k.Token, ExpiresAt: v.ExpiresAt.UTC(),
		ReturnConsumedCapacity:      v.ReturnConsumedCapacity,
		ReturnItemCollectionMetrics: v.ReturnItemCollectionMetrics,
		CanceledRequest:             v.CanceledRequest,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteTransactionCapacityReads(w.ctx, sqlcgen.DeleteTransactionCapacityReadsParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: k.Token,
	}); err != nil {
		return err
	}
	for i, charge := range v.Read {
		if err := w.q.PutTransactionCapacityRead(w.ctx, sqlcgen.PutTransactionCapacityReadParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Token: k.Token,
			Position: int64(i), TableName: charge.TableName, Units: charge.Units,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteExpiredTransactionCapacities(cutoff time.Time) error {
	return w.q.DeleteExpiredTransactionCapacities(w.ctx, cutoff.UTC())
}
