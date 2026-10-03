-- name: GetGlueCatalog :one
SELECT * FROM glue_catalogs WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ?;

-- name: PutGlueCatalog :exec
INSERT INTO glue_catalogs (partition, account_id, region, catalog_id, name, description, created_at, updated_at, parameters_json, database_permissions_json, table_permissions_json, full_table_access, tags_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id) DO UPDATE SET name = excluded.name, description = excluded.description, created_at = excluded.created_at, updated_at = excluded.updated_at, parameters_json = excluded.parameters_json, database_permissions_json = excluded.database_permissions_json, table_permissions_json = excluded.table_permissions_json, full_table_access = excluded.full_table_access, tags_json = excluded.tags_json;

-- name: DeleteGlueCatalog :exec
DELETE FROM glue_catalogs WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ?;

-- name: ListGlueCatalogs :many
SELECT * FROM glue_catalogs WHERE partition = ? AND account_id = ? AND region = ? ORDER BY catalog_id;

-- name: GetGlueDatabase :one
SELECT * FROM glue_databases WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ?;

-- name: PutGlueDatabase :exec
INSERT INTO glue_databases (partition, account_id, region, catalog_id, database_name, description, location_uri, created_at, parameters_json, default_permissions_json, target_database_json, tags_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name) DO UPDATE SET description = excluded.description, location_uri = excluded.location_uri, created_at = excluded.created_at, parameters_json = excluded.parameters_json, default_permissions_json = excluded.default_permissions_json, target_database_json = excluded.target_database_json, tags_json = excluded.tags_json;

-- name: DeleteGlueDatabase :exec
DELETE FROM glue_databases WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ?;

-- name: ListGlueDatabases :many
SELECT * FROM glue_databases WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? ORDER BY database_name;

-- name: GetGlueTable :one
SELECT * FROM glue_tables WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ?;

-- name: PutGlueTable :exec
INSERT INTO glue_tables (partition, account_id, region, catalog_id, database_name, table_name, version, description, owner, created_by, created_at, updated_at, last_access_at, last_analyzed_at, retention, storage_descriptor_json, partition_keys_json, parameters_json, table_type, target_table_json, view_original_text, view_expanded_text)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name) DO UPDATE SET version = excluded.version, description = excluded.description, owner = excluded.owner, created_by = excluded.created_by, created_at = excluded.created_at, updated_at = excluded.updated_at, last_access_at = excluded.last_access_at, last_analyzed_at = excluded.last_analyzed_at, retention = excluded.retention, storage_descriptor_json = excluded.storage_descriptor_json, partition_keys_json = excluded.partition_keys_json, parameters_json = excluded.parameters_json, table_type = excluded.table_type, target_table_json = excluded.target_table_json, view_original_text = excluded.view_original_text, view_expanded_text = excluded.view_expanded_text;

-- name: DeleteGlueTable :exec
DELETE FROM glue_tables WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ?;

-- name: ListGlueTables :many
SELECT * FROM glue_tables WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? ORDER BY table_name;

-- name: GetGlueTableVersion :one
SELECT * FROM glue_table_versions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND version = ?;

-- name: PutGlueTableVersion :exec
INSERT INTO glue_table_versions (partition, account_id, region, catalog_id, database_name, table_name, version, description, owner, created_by, created_at, updated_at, last_access_at, last_analyzed_at, retention, storage_descriptor_json, partition_keys_json, parameters_json, table_type, target_table_json, view_original_text, view_expanded_text)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name, version) DO UPDATE SET description = excluded.description, owner = excluded.owner, created_by = excluded.created_by, created_at = excluded.created_at, updated_at = excluded.updated_at, last_access_at = excluded.last_access_at, last_analyzed_at = excluded.last_analyzed_at, retention = excluded.retention, storage_descriptor_json = excluded.storage_descriptor_json, partition_keys_json = excluded.partition_keys_json, parameters_json = excluded.parameters_json, table_type = excluded.table_type, target_table_json = excluded.target_table_json, view_original_text = excluded.view_original_text, view_expanded_text = excluded.view_expanded_text;

-- name: DeleteGlueTableVersion :exec
DELETE FROM glue_table_versions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND version = ?;

-- name: ListGlueTableVersions :many
SELECT * FROM glue_table_versions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? ORDER BY version;

-- name: GetGluePartition :one
SELECT * FROM glue_partitions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ?;

-- name: PutGluePartition :exec
INSERT INTO glue_partitions (partition, account_id, region, catalog_id, database_name, table_name, values_json, created_at, last_access_at, last_analyzed_at, parameters_json, storage_descriptor_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name, values_json) DO UPDATE SET created_at = excluded.created_at, last_access_at = excluded.last_access_at, last_analyzed_at = excluded.last_analyzed_at, parameters_json = excluded.parameters_json, storage_descriptor_json = excluded.storage_descriptor_json;

-- name: DeleteGluePartition :exec
DELETE FROM glue_partitions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ?;

-- name: ListGluePartitions :many
SELECT * FROM glue_partitions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? ORDER BY values_json;

-- name: GetGlueFunction :one
SELECT * FROM glue_functions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND function_name = ?;

-- name: PutGlueFunction :exec
INSERT INTO glue_functions (partition, account_id, region, catalog_id, database_name, function_name, class_name, function_type, owner_name, owner_type, created_at, resource_uris_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, function_name) DO UPDATE SET class_name = excluded.class_name, function_type = excluded.function_type, owner_name = excluded.owner_name, owner_type = excluded.owner_type, created_at = excluded.created_at, resource_uris_json = excluded.resource_uris_json;

-- name: DeleteGlueFunction :exec
DELETE FROM glue_functions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND function_name = ?;

-- name: ListGlueFunctions :many
SELECT * FROM glue_functions WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? ORDER BY function_name;

-- name: GetGluePartitionIndex :one
SELECT * FROM glue_partition_indexes WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND index_name = ?;

-- name: PutGluePartitionIndex :exec
INSERT INTO glue_partition_indexes (partition, account_id, region, catalog_id, database_name, table_name, index_name, status, keys_json, backfill_errors_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name, index_name) DO UPDATE SET status = excluded.status, keys_json = excluded.keys_json, backfill_errors_json = excluded.backfill_errors_json;

-- name: DeleteGluePartitionIndex :exec
DELETE FROM glue_partition_indexes WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND index_name = ?;

-- name: ListGluePartitionIndexes :many
SELECT * FROM glue_partition_indexes WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? ORDER BY index_name;

-- name: GetGlueColumnStatistics :one
SELECT * FROM glue_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND column_name = ?;

-- name: PutGlueColumnStatistics :exec
INSERT INTO glue_column_statistics (partition, account_id, region, catalog_id, database_name, table_name, column_name, column_type, analyzed_at, statistics_data_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name, column_name) DO UPDATE SET column_type = excluded.column_type, analyzed_at = excluded.analyzed_at, statistics_data_json = excluded.statistics_data_json;

-- name: DeleteGlueColumnStatistics :exec
DELETE FROM glue_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND column_name = ?;

-- name: GetGluePartitionColumnStatistics :one
SELECT * FROM glue_partition_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ? AND column_name = ?;

-- name: ListGluePartitionStatistics :many
SELECT * FROM glue_partition_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ? ORDER BY column_name;

-- name: PutGluePartitionColumnStatistics :exec
INSERT INTO glue_partition_column_statistics (partition, account_id, region, catalog_id, database_name, table_name, values_json, column_name, column_type, analyzed_at, statistics_data_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id, database_name, table_name, values_json, column_name) DO UPDATE SET column_type = excluded.column_type, analyzed_at = excluded.analyzed_at, statistics_data_json = excluded.statistics_data_json;

-- name: DeleteGluePartitionColumnStatistics :exec
DELETE FROM glue_partition_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ? AND column_name = ?;

-- name: DeleteGluePartitionStatistics :exec
DELETE FROM glue_partition_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND values_json = ?;

-- name: DeleteGluePartitionColumnStatisticsForColumn :exec
DELETE FROM glue_partition_column_statistics WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ? AND database_name = ? AND table_name = ? AND column_name = ?;

-- name: GetGlueResourcePolicy :one
SELECT * FROM glue_resource_policies WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutGlueResourcePolicy :exec
INSERT INTO glue_resource_policies (partition, account_id, region, document, principal_ids_json, policy_hash, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET document = excluded.document, principal_ids_json = excluded.principal_ids_json, policy_hash = excluded.policy_hash, created_at = excluded.created_at, updated_at = excluded.updated_at;

-- name: DeleteGlueResourcePolicy :exec
DELETE FROM glue_resource_policies WHERE partition = ? AND account_id = ? AND region = ?;

-- name: GetGlueCatalogImport :one
SELECT * FROM glue_catalog_imports WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ?;

-- name: PutGlueCatalogImport :exec
INSERT INTO glue_catalog_imports (partition, account_id, region, catalog_id, completed, imported_at, imported_by)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, catalog_id) DO UPDATE SET completed = excluded.completed, imported_at = excluded.imported_at, imported_by = excluded.imported_by;

-- name: DeleteGlueCatalogImport :exec
DELETE FROM glue_catalog_imports WHERE partition = ? AND account_id = ? AND region = ? AND catalog_id = ?;

-- name: ListGlueForeignDatabases :many
SELECT * FROM glue_databases
WHERE partition = ? AND account_id <> ? AND region = ?
ORDER BY database_name, catalog_id;
