-- name: SetTableReplica :exec
UPDATE dynamodb_tables SET replica_group_id = ?, replica_cursor = ?, replica_last_source_at = ?, replica_unauthorized_at = ?, replica_settings_pending = ?
WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListReplicaTables :many
SELECT * FROM dynamodb_tables
WHERE replica_group_id <> '' AND (replica_group_id = sqlc.arg(group_id) OR sqlc.arg(group_id) = '')
ORDER BY partition, account_id, region, name;

-- name: GetReplicaBootstrap :one
SELECT * FROM dynamodb_replica_bootstraps WHERE partition = ? AND account_id = ? AND region = ? AND table_name = ?;

-- name: ListReplicaBootstraps :many
SELECT * FROM dynamodb_replica_bootstraps
WHERE source_database_id = sqlc.arg(database_id) OR sqlc.arg(database_id) = ''
ORDER BY partition, account_id, region, table_name;

-- name: PutReplicaBootstrap :exec
INSERT INTO dynamodb_replica_bootstraps (
 partition, account_id, region, table_name, source_partition, source_account_id, source_region,
 source_table_name, source_database_id, source_physical_name, snapshot_physical_name,
 key_schema, attribute_definitions, ready, copied, cursor
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, table_name) DO UPDATE SET
 source_partition = excluded.source_partition, source_account_id = excluded.source_account_id,
 source_region = excluded.source_region, source_table_name = excluded.source_table_name,
 source_database_id = excluded.source_database_id, source_physical_name = excluded.source_physical_name,
 snapshot_physical_name = excluded.snapshot_physical_name, key_schema = excluded.key_schema,
 attribute_definitions = excluded.attribute_definitions, ready = excluded.ready, copied = excluded.copied,
 cursor = excluded.cursor;

-- name: DeleteReplicaBootstrap :exec
DELETE FROM dynamodb_replica_bootstraps WHERE partition = ? AND account_id = ? AND region = ? AND table_name = ?;

-- name: DeleteReplicaPinnedVersions :exec
DELETE FROM dynamodb_replica_pinned_versions WHERE partition = ? AND account_id = ? AND region = ? AND table_name = ?;

-- name: SnapshotReplicaVersions :exec
INSERT INTO dynamodb_replica_pinned_versions (partition, account_id, region, table_name, key_id, version)
SELECT sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(table_name), key_id, version
FROM dynamodb_replica_versions WHERE physical_name = sqlc.arg(source_physical_name);

-- name: InstallReplicaVersions :exec
INSERT INTO dynamodb_replica_versions (physical_name, key_id, version)
SELECT sqlc.arg(target_physical_name), key_id, version FROM dynamodb_replica_pinned_versions
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND table_name = sqlc.arg(table_name);

-- name: GetReplicaVersion :one
SELECT CAST(COALESCE(MAX(version), 0) AS INTEGER) FROM dynamodb_replica_versions WHERE physical_name = ? AND key_id = ?;

-- name: PutReplicaVersion :exec
INSERT INTO dynamodb_replica_versions (physical_name, key_id, version) VALUES (?, ?, ?)
ON CONFLICT (physical_name, key_id) DO UPDATE SET version = excluded.version;

-- name: DeleteReplicaVersions :exec
DELETE FROM dynamodb_replica_versions WHERE physical_name = ?;

-- name: GetReplicaSequence :one
SELECT CAST(COALESCE(MAX(sequence), 0) AS INTEGER) FROM dynamodb_replica_changes WHERE group_id = ?;

-- name: GetReplicaChange :one
SELECT * FROM dynamodb_replica_changes WHERE group_id = ? AND sequence = ?;

-- name: ListReplicaChanges :many
SELECT * FROM dynamodb_replica_changes WHERE group_id = ? AND sequence > sqlc.arg(after_sequence)
ORDER BY sequence LIMIT sqlc.arg(row_limit);

-- name: AppendReplicaChange :exec
INSERT INTO dynamodb_replica_changes (
 group_id, version, at, origin_partition, origin_account_id, origin_region,
 origin_table_name, origin_physical_name, key_id, key_data, item_data
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TrimReplicaChanges :exec
DELETE FROM dynamodb_replica_changes
WHERE group_id = sqlc.arg(group_id) AND sequence <= sqlc.arg(through_sequence);

-- name: TrimReplicaVersions :exec
DELETE FROM dynamodb_replica_versions
WHERE physical_name IN (SELECT physical_name FROM dynamodb_tables WHERE replica_group_id = sqlc.arg(group_id))
AND NOT EXISTS (
 SELECT 1 FROM dynamodb_replica_changes c
 WHERE c.group_id = sqlc.arg(group_id) AND c.version <= dynamodb_replica_versions.version
)
AND NOT EXISTS (
 SELECT 1 FROM dynamodb_mutation_captures c
 JOIN dynamodb_mutation_sources s ON s.database_id = c.database_id
 WHERE s.replication_group_id = sqlc.arg(group_id) AND c.version <= dynamodb_replica_versions.version
);
