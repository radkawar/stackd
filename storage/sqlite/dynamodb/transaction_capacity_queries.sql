-- name: GetTransactionCapacity :one
SELECT expires_at,return_consumed_capacity,return_item_collection_metrics,canceled_request FROM dynamodb_transaction_capacities
WHERE partition=? AND account_id=? AND region=? AND token=?;

-- name: GetTransactionCapacityReads :many
SELECT table_name,units FROM dynamodb_transaction_capacity_reads
WHERE partition=? AND account_id=? AND region=? AND token=?
ORDER BY position;

-- name: PutTransactionCapacity :exec
INSERT INTO dynamodb_transaction_capacities(partition,account_id,region,token,expires_at,return_consumed_capacity,return_item_collection_metrics,canceled_request)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,token) DO UPDATE SET
expires_at=excluded.expires_at,return_consumed_capacity=excluded.return_consumed_capacity,
return_item_collection_metrics=excluded.return_item_collection_metrics,canceled_request=excluded.canceled_request;

-- name: DeleteTransactionCapacityReads :exec
DELETE FROM dynamodb_transaction_capacity_reads
WHERE partition=? AND account_id=? AND region=? AND token=?;

-- name: PutTransactionCapacityRead :exec
INSERT INTO dynamodb_transaction_capacity_reads(partition,account_id,region,token,position,table_name,units)
VALUES(?,?,?,?,?,?,?);

-- name: DeleteExpiredTransactionCapacities :exec
DELETE FROM dynamodb_transaction_capacities WHERE expires_at<=sqlc.arg(cutoff);
