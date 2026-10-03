package dynamodb

import "time"

// TransactionCapacityKey follows the regional token namespace shared by native
// TransactWriteItems and ExecuteTransaction, independently of any one table.
type TransactionCapacityKey struct {
	Scope
	Token string
}

// TransactionCapacity retains the read charge of a completed native transaction.
// Replays charge its original item sizes even after those items change or vanish.
// It also retains response modes and canceled request identity, which AWS binds
// to the token but the native engine ignores. Native execution remains external.
type TransactionCapacity struct {
	Key                         TransactionCapacityKey
	ExpiresAt                   time.Time
	ReturnConsumedCapacity      string
	ReturnItemCollectionMetrics string
	CanceledRequest             string
	Read                        []TransactionReadCapacity
}

// TransactionReadCapacity is a retained table-only replay charge. Index writes
// are not replayed and must never be carried into the replay's read units.
type TransactionReadCapacity struct {
	TableName string
	Units     float64
}

type TransactionCapacityReader interface {
	TransactionCapacity(TransactionCapacityKey) (TransactionCapacity, error)
}

type TransactionCapacityWriter interface {
	PutTransactionCapacity(TransactionCapacity) error
	DeleteExpiredTransactionCapacities(time.Time) error
}
