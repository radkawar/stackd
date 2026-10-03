-- name: ListKinesisDestinations :many
SELECT * FROM dynamodb_kinesis_destinations ORDER BY id;

-- name: PutKinesisDestination :exec
INSERT INTO dynamodb_kinesis_destinations (
 id, partition, account_id, region, table_name, physical_name, stream_arn,
 status, description, precision, pending_precision, admission_failure, superseded, due, capture_until
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET status=excluded.status, description=excluded.description,
 precision=excluded.precision, pending_precision=excluded.pending_precision,
 admission_failure=excluded.admission_failure, superseded=excluded.superseded,
 due=excluded.due, capture_until=excluded.capture_until;

-- name: ListKinesisDeliveries :many
SELECT * FROM dynamodb_kinesis_deliveries ORDER BY due,id;

-- name: PutKinesisDelivery :exec
INSERT INTO dynamodb_kinesis_deliveries (
 id, destination_id, partition, account_id, region, table_name, stream_arn,
 partition_key, data, parent_event_id, due, attempts, last_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET due=excluded.due, attempts=excluded.attempts, last_error=excluded.last_error;

-- name: DeleteKinesisDelivery :exec
DELETE FROM dynamodb_kinesis_deliveries WHERE id=?;

-- name: ListMutationKinesisConsumers :many
SELECT * FROM dynamodb_mutation_kinesis_consumers WHERE database_id=? AND source_position=? ORDER BY destination_id;

-- name: PutMutationKinesisConsumer :exec
INSERT INTO dynamodb_mutation_kinesis_consumers (database_id,source_position,destination_id,stream_arn,precision,capture_until)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListActiveKinesisConsumers :many
SELECT id, stream_arn, precision, capture_until FROM dynamodb_kinesis_destinations
WHERE physical_name=? AND (status IN ('ACTIVE','UPDATING','DISABLING') OR status='DISABLED' AND capture_until > '0001-01-01 00:00:00+00:00')
ORDER BY id;

-- name: NextKinesisDelivery :one
SELECT id,due FROM dynamodb_kinesis_deliveries ORDER BY due,id LIMIT 1;

-- name: GetKinesisDelivery :one
SELECT * FROM dynamodb_kinesis_deliveries WHERE id=?;
