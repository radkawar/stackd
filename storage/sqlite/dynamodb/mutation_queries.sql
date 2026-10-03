-- name: GetActiveWriteConsumers :one
SELECT recovery_id, replica_group_id FROM dynamodb_tables
WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND physical_name = ?;

-- name: GetMutationCapture :one
SELECT * FROM dynamodb_mutation_captures WHERE database_id = ?;

-- name: ListMutationSources :many
SELECT * FROM dynamodb_mutation_sources WHERE database_id = ? ORDER BY position;

-- name: ListMutationItems :many
SELECT * FROM dynamodb_mutation_items WHERE database_id = ? AND source_position = ? ORDER BY position;

-- name: CreateMutationCapture :one
INSERT INTO dynamodb_mutation_captures (database_id, at, parent_event_id, transactional, ttl) VALUES (?, ?, ?, ?, ?) RETURNING version;

-- name: DeleteMutationCapture :exec
DELETE FROM dynamodb_mutation_captures WHERE database_id = ?;

-- name: PutMutationSource :exec
INSERT INTO dynamodb_mutation_sources (
 database_id, position, partition, account_id, region, table_name, physical_name,
 key_schema, recovery_id, replication_group_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PutMutationItem :exec
INSERT INTO dynamodb_mutation_items (
 database_id, source_position, position, key_data, before_data, replica_sequence
) VALUES (?, ?, ?, ?, ?, ?);
