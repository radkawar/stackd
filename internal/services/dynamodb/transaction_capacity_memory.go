package dynamodb

import (
	"slices"
	"time"
)

func (r memoryReader) TransactionCapacity(k TransactionCapacityKey) (TransactionCapacity, error) {
	if err := r.tx.Check(false); err != nil {
		return TransactionCapacity{}, err
	}
	v, ok := r.s.transactionCapacities[k]
	if !ok {
		return TransactionCapacity{}, ErrNotFound
	}
	v.Read = slices.Clone(v.Read)
	return v, nil
}

func (w memoryWriter) PutTransactionCapacity(v TransactionCapacity) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Read = slices.Clone(v.Read)
	w.s.transactionCapacities[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteExpiredTransactionCapacities(cutoff time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, v := range w.s.transactionCapacities {
		if !v.ExpiresAt.After(cutoff) {
			delete(w.s.transactionCapacities, k)
		}
	}
	return nil
}
