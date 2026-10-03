-- name: GetBackup :one
SELECT * FROM dynamodb_backups WHERE partition = ? AND account_id = ? AND region = ? AND table_name = ? AND backup_id = ?;

-- name: ListBackups :many
SELECT * FROM dynamodb_backups
WHERE partition = ? AND account_id = ? AND region = ? AND backup_status != 'DELETED'
AND (backup_type = sqlc.arg(kind) OR sqlc.arg(kind) = '')
AND (backup_expires_at IS NULL OR backup_expires_at > sqlc.arg(at))
AND (table_name = sqlc.arg(source_table) OR sqlc.arg(source_table) = '')
AND backup_arn > sqlc.arg(after_arn)
AND (backup_created_at >= sqlc.narg(lower_time) OR sqlc.narg(lower_time) IS NULL)
AND (backup_created_at <= sqlc.narg(upper_time) OR sqlc.narg(upper_time) IS NULL)
ORDER BY backup_arn LIMIT sqlc.arg(row_limit);

-- name: ListPendingBackups :many
SELECT * FROM dynamodb_backups
WHERE backup_status IN ('CREATING', 'DELETED')
OR (backup_status = 'AVAILABLE' AND backup_expires_at <= sqlc.arg(now))
ORDER BY backup_arn;

-- name: NextBackupExpiry :one
SELECT backup_expires_at FROM dynamodb_backups
WHERE backup_status != 'DELETED' AND backup_expires_at > sqlc.arg(after)
ORDER BY backup_expires_at LIMIT 1;

-- name: ListUncapturedBackups :many
SELECT * FROM dynamodb_backups WHERE backup_status = 'CREATING' AND database_id = ? ORDER BY backup_arn;

-- name: HasDatabaseBackups :one
SELECT EXISTS(SELECT 1 FROM dynamodb_backups WHERE database_id = ?);

-- name: PutBackup :exec
INSERT INTO dynamodb_backups (
 partition, account_id, region, table_name, backup_id, backup_arn, database_id, physical_name, source_physical_name,
 backup_name, backup_created_at, backup_status, backup_size_bytes, source_table_id, source_created_at,
 source_billing_mode, source_item_count, source_size_bytes, attribute_definitions, source_key_schema,
 source_provisioned_throughput, source_on_demand_throughput, source_global_secondary_indexes,
 source_local_secondary_indexes, source_stream_description, source_ttl_attribute_name, source_ttl_status,
 backup_type, backup_expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, table_name, backup_id) DO UPDATE SET
 backup_arn = excluded.backup_arn, database_id = excluded.database_id, physical_name = excluded.physical_name,
 source_physical_name = excluded.source_physical_name, backup_name = excluded.backup_name,
 backup_created_at = excluded.backup_created_at, backup_status = excluded.backup_status,
 backup_size_bytes = excluded.backup_size_bytes, source_table_id = excluded.source_table_id,
 source_created_at = excluded.source_created_at, source_billing_mode = excluded.source_billing_mode,
 source_item_count = excluded.source_item_count, source_size_bytes = excluded.source_size_bytes,
 attribute_definitions = excluded.attribute_definitions, source_key_schema = excluded.source_key_schema,
 source_provisioned_throughput = excluded.source_provisioned_throughput,
 source_on_demand_throughput = excluded.source_on_demand_throughput,
 source_global_secondary_indexes = excluded.source_global_secondary_indexes,
 source_local_secondary_indexes = excluded.source_local_secondary_indexes,
 source_stream_description = excluded.source_stream_description,
 source_ttl_attribute_name = excluded.source_ttl_attribute_name, source_ttl_status = excluded.source_ttl_status,
 backup_type = excluded.backup_type, backup_expires_at = excluded.backup_expires_at;

-- name: DeleteBackup :exec
DELETE FROM dynamodb_backups WHERE partition = ? AND account_id = ? AND region = ? AND table_name = ? AND backup_id = ?;
