-- name: GetRecovery :one
SELECT * FROM dynamodb_recoveries WHERE id = ?;

-- name: ListRecoveries :many
SELECT * FROM dynamodb_recoveries
WHERE database_id = sqlc.arg(database_id) OR sqlc.arg(database_id) = ''
ORDER BY id;

-- name: ListUnsettledRecoveries :many
SELECT * FROM dynamodb_recoveries
WHERE database_id = ? AND (snapshot_at IS NULL OR compact_through IS NOT NULL)
ORDER BY id;

-- name: PutRecovery :exec
INSERT INTO dynamodb_recoveries (
 id, partition, account_id, region, table_name, database_id, source_physical_name,
 physical_name, key_schema, attribute_definitions, recovery_period_in_days,
 earliest_at, snapshot_at, compact_through
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
 partition = excluded.partition, account_id = excluded.account_id, region = excluded.region,
 table_name = excluded.table_name, database_id = excluded.database_id,
 source_physical_name = excluded.source_physical_name, physical_name = excluded.physical_name,
 key_schema = excluded.key_schema, attribute_definitions = excluded.attribute_definitions,
 recovery_period_in_days = excluded.recovery_period_in_days, earliest_at = excluded.earliest_at,
 snapshot_at = excluded.snapshot_at, compact_through = excluded.compact_through;

-- name: DeleteRecovery :exec
DELETE FROM dynamodb_recoveries WHERE id = ?;

-- name: GetRecoverySequence :one
SELECT CAST(COALESCE(MAX(sequence), 0) AS INTEGER) FROM dynamodb_recovery_changes WHERE recovery_id = ?;

-- name: ListRecoveryChanges :many
SELECT * FROM dynamodb_recovery_changes
WHERE recovery_id = ? AND sequence > sqlc.arg(after_sequence)
AND (at <= sqlc.narg(through_time) OR sqlc.narg(through_time) IS NULL)
AND (sequence <= sqlc.narg(through_sequence) OR sqlc.narg(through_sequence) IS NULL)
ORDER BY sequence LIMIT sqlc.arg(row_limit);

-- name: AppendRecoveryChange :exec
INSERT INTO dynamodb_recovery_changes (recovery_id, at, key_data, item_data)
VALUES (?, ?, ?, ?);

-- name: DeleteRecoveryChanges :exec
DELETE FROM dynamodb_recovery_changes WHERE recovery_id = ? AND at <= sqlc.arg(through_time);

