
-- name: PutDatabase :exec
INSERT INTO dynamodb_databases (id, partition, account_id, region, retiring)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET partition = excluded.partition, account_id = excluded.account_id, region = excluded.region, retiring = excluded.retiring;

-- name: GetDatabase :one
SELECT * FROM dynamodb_databases WHERE partition = ? AND account_id = ? AND region = ? AND retiring = 0;

-- name: DeleteDatabase :exec
DELETE FROM dynamodb_databases WHERE id = ?;

-- name: PutTable :exec
INSERT INTO dynamodb_tables (partition, account_id, region, name, database_id, physical_name, archival_summary, attribute_definitions, billing_mode_summary, creation_date_time, deletion_protection_enabled, global_secondary_indexes, global_table_settings_replication_mode, global_table_version, global_table_witnesses, item_count, key_schema, latest_stream_arn, latest_stream_label, local_secondary_indexes, multi_region_consistency, on_demand_throughput, provisioned_throughput, replicas, restore_summary, sse_description, stream_specification, table_arn, table_class_summary, table_id, table_name, table_size_bytes, table_status, vector_indexes, warm_throughput, ttl_attribute_name, ttl_status, ttl_changed_at, ttl_next_scan, metrics_next_at, recovery_id, restore_recovery_id, restore_recovery_sequence)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET database_id = excluded.database_id, physical_name = excluded.physical_name, archival_summary = excluded.archival_summary, attribute_definitions = excluded.attribute_definitions, billing_mode_summary = excluded.billing_mode_summary, creation_date_time = excluded.creation_date_time, deletion_protection_enabled = excluded.deletion_protection_enabled, global_secondary_indexes = excluded.global_secondary_indexes, global_table_settings_replication_mode = excluded.global_table_settings_replication_mode, global_table_version = excluded.global_table_version, global_table_witnesses = excluded.global_table_witnesses, item_count = excluded.item_count, key_schema = excluded.key_schema, latest_stream_arn = excluded.latest_stream_arn, latest_stream_label = excluded.latest_stream_label, local_secondary_indexes = excluded.local_secondary_indexes, multi_region_consistency = excluded.multi_region_consistency, on_demand_throughput = excluded.on_demand_throughput, provisioned_throughput = excluded.provisioned_throughput, replicas = excluded.replicas, restore_summary = excluded.restore_summary, sse_description = excluded.sse_description, stream_specification = excluded.stream_specification, table_arn = excluded.table_arn, table_class_summary = excluded.table_class_summary, table_id = excluded.table_id, table_name = excluded.table_name, table_size_bytes = excluded.table_size_bytes, table_status = excluded.table_status, vector_indexes = excluded.vector_indexes, warm_throughput = excluded.warm_throughput, ttl_attribute_name = excluded.ttl_attribute_name, ttl_status = excluded.ttl_status, ttl_changed_at = excluded.ttl_changed_at, ttl_next_scan = excluded.ttl_next_scan, metrics_next_at = excluded.metrics_next_at, recovery_id = excluded.recovery_id, restore_recovery_id = excluded.restore_recovery_id, restore_recovery_sequence = excluded.restore_recovery_sequence;

-- name: GetTable :one
SELECT * FROM dynamodb_tables WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeleteTable :exec
DELETE FROM dynamodb_tables WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListOnDemandSwitches :many
SELECT switched_at FROM dynamodb_on_demand_switches
WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY position;

-- name: DeleteOnDemandSwitches :exec
DELETE FROM dynamodb_on_demand_switches WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutOnDemandSwitch :exec
INSERT INTO dynamodb_on_demand_switches (partition, account_id, region, name, position, switched_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: PutPendingCreate :exec
INSERT INTO dynamodb_pending_creates (partition, account_id, region, name, attribute_definitions, billing_mode, deletion_protection_enabled, global_secondary_indexes, global_table_settings_replication_mode, global_table_source_arn, key_schema, local_secondary_indexes, on_demand_throughput, provisioned_throughput, resource_policy, sse_specification, stream_specification, table_class, table_name, vector_indexes, warm_throughput, tags_present)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET attribute_definitions = excluded.attribute_definitions, billing_mode = excluded.billing_mode, deletion_protection_enabled = excluded.deletion_protection_enabled, global_secondary_indexes = excluded.global_secondary_indexes, global_table_settings_replication_mode = excluded.global_table_settings_replication_mode, global_table_source_arn = excluded.global_table_source_arn, key_schema = excluded.key_schema, local_secondary_indexes = excluded.local_secondary_indexes, on_demand_throughput = excluded.on_demand_throughput, provisioned_throughput = excluded.provisioned_throughput, resource_policy = excluded.resource_policy, sse_specification = excluded.sse_specification, stream_specification = excluded.stream_specification, table_class = excluded.table_class, table_name = excluded.table_name, vector_indexes = excluded.vector_indexes, warm_throughput = excluded.warm_throughput, tags_present = excluded.tags_present;

-- name: GetPendingCreate :one
SELECT * FROM dynamodb_pending_creates WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeletePendingCreate :exec
DELETE FROM dynamodb_pending_creates WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutPendingUpdate :exec
INSERT INTO dynamodb_pending_updates (partition, account_id, region, name, attribute_definitions, billing_mode, deletion_protection_enabled, global_secondary_index_updates, global_table_settings_replication_mode, global_table_witness_updates, multi_region_consistency, on_demand_throughput, provisioned_throughput, replica_updates, sse_specification, stream_specification, table_class, table_name, vector_index_updates, warm_throughput, accepted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET attribute_definitions = excluded.attribute_definitions, billing_mode = excluded.billing_mode, deletion_protection_enabled = excluded.deletion_protection_enabled, global_secondary_index_updates = excluded.global_secondary_index_updates, global_table_settings_replication_mode = excluded.global_table_settings_replication_mode, global_table_witness_updates = excluded.global_table_witness_updates, multi_region_consistency = excluded.multi_region_consistency, on_demand_throughput = excluded.on_demand_throughput, provisioned_throughput = excluded.provisioned_throughput, replica_updates = excluded.replica_updates, sse_specification = excluded.sse_specification, stream_specification = excluded.stream_specification, table_class = excluded.table_class, table_name = excluded.table_name, vector_index_updates = excluded.vector_index_updates, warm_throughput = excluded.warm_throughput, accepted_at = excluded.accepted_at;

-- name: GetPendingUpdate :one
SELECT * FROM dynamodb_pending_updates WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeletePendingUpdate :exec
DELETE FROM dynamodb_pending_updates WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutTagSet :exec
INSERT INTO dynamodb_tag_sets (partition, account_id, region, name, tags_present)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET tags_present = excluded.tags_present;

-- name: GetTagSet :one
SELECT * FROM dynamodb_tag_sets WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeleteTagSet :exec
DELETE FROM dynamodb_tag_sets WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutTag :exec
INSERT INTO dynamodb_tags (partition, account_id, region, name, position, key, value)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: ListTags :many
SELECT * FROM dynamodb_tags WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY position;

-- name: DeleteTags :exec
DELETE FROM dynamodb_tags WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutCreateTag :exec
INSERT INTO dynamodb_create_tags (partition, account_id, region, name, position, key, value)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: ListCreateTags :many
SELECT * FROM dynamodb_create_tags WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY position;

-- name: DeleteCreateTags :exec
DELETE FROM dynamodb_create_tags WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutPolicy :exec
INSERT INTO dynamodb_policies (partition, account_id, region, resource_arn, document, revision, principals_present)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, resource_arn) DO UPDATE SET document = excluded.document, revision = excluded.revision, principals_present = excluded.principals_present;

-- name: GetPolicy :one
SELECT * FROM dynamodb_policies WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: DeletePolicy :exec
DELETE FROM dynamodb_policies WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: ListPolicyPrincipals :many
SELECT principal_arn, principal_id FROM dynamodb_policy_principals
WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ? ORDER BY principal_arn;

-- name: PutPolicyPrincipal :exec
INSERT INTO dynamodb_policy_principals (partition, account_id, region, resource_arn, principal_arn, principal_id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeletePolicyPrincipals :exec
DELETE FROM dynamodb_policy_principals WHERE partition = ? AND account_id = ? AND region = ? AND resource_arn = ?;

-- name: ListDatabases :many
SELECT * FROM dynamodb_databases ORDER BY partition, account_id, region, id;

-- name: ListTables :many
SELECT * FROM dynamodb_tables
WHERE partition = ? AND account_id = ? AND region = ? AND name > sqlc.arg(after_name)
ORDER BY name COLLATE BINARY LIMIT sqlc.arg(row_limit);

-- name: ListPendingTables :many
SELECT * FROM dynamodb_tables WHERE table_status IN ('CREATING', 'UPDATING', 'DELETING')
ORDER BY partition, account_id, region, name;

-- name: ListTTLTables :many
SELECT * FROM dynamodb_tables WHERE ttl_status = 'ENABLED' AND table_status IN ('ACTIVE', 'UPDATING')
ORDER BY ttl_next_scan, partition, account_id, region, name;

-- name: GetStream :one
SELECT * FROM dynamodb_streams WHERE partition = ? AND account_id = ? AND region = ? AND stream_arn = ?;
-- name: ListStreams :many
SELECT * FROM dynamodb_streams ORDER BY stream_arn;
-- name: PutStream :exec
INSERT INTO dynamodb_streams (stream_arn, partition, account_id, region, table_name, database_id, physical_name, native_arn, label, created_at, closed_at, view_type, key_schema)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stream_arn) DO UPDATE SET closed_at=excluded.closed_at;
-- name: DeleteStream :exec
DELETE FROM dynamodb_streams WHERE partition = ? AND account_id = ? AND region = ? AND stream_arn = ?;
-- name: ListStreamShards :many
SELECT * FROM dynamodb_stream_shards WHERE stream_arn = ? ORDER BY shard_id;
-- name: PutStreamShard :exec
INSERT INTO dynamodb_stream_shards(stream_arn, shard_id, parent_id, start_sequence, end_sequence, checkpoint, trimmed_through, drained)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stream_arn, shard_id) DO UPDATE SET parent_id=excluded.parent_id, start_sequence=excluded.start_sequence, end_sequence=excluded.end_sequence, checkpoint=excluded.checkpoint, trimmed_through=excluded.trimmed_through, drained=excluded.drained;
-- name: ListStreamEntries :many
WITH candidates AS (
 SELECT sequence, size_bytes FROM dynamodb_stream_entries
 WHERE stream_arn = sqlc.arg(stream_arn) AND shard_id = sqlc.arg(shard_id)
 AND (length(ltrim(sequence, '0')), ltrim(sequence, '0')) >=
     (length(ltrim(CAST(sqlc.arg(position) AS TEXT), '0')), ltrim(CAST(sqlc.arg(position) AS TEXT), '0'))
 AND (CAST(sqlc.arg(inclusive) AS BOOLEAN) OR ltrim(sequence, '0') != ltrim(CAST(sqlc.arg(position) AS TEXT), '0'))
 ORDER BY length(ltrim(sequence, '0')), ltrim(sequence, '0'), sequence
 LIMIT CAST(sqlc.arg(record_limit) AS INTEGER)
), bounded AS (
 SELECT sequence, SUM(COALESCE(size_bytes, 0)) OVER (
  ORDER BY length(ltrim(sequence, '0')), ltrim(sequence, '0'), sequence ROWS UNBOUNDED PRECEDING
 ) AS total_bytes FROM candidates
)
SELECT e.* FROM dynamodb_stream_entries AS e
JOIN bounded AS b ON e.sequence = b.sequence
WHERE e.stream_arn = sqlc.arg(stream_arn) AND e.shard_id = sqlc.arg(shard_id) AND b.total_bytes <= 1048576
ORDER BY length(ltrim(e.sequence, '0')), ltrim(e.sequence, '0'), e.sequence;
-- name: PutStreamEntry :exec
INSERT INTO dynamodb_stream_entries(stream_arn, shard_id, sequence, created_at, event_id, event_name, event_source, event_version, aws_region, identity_type, identity_principal, size_bytes, view_type, keys_data, new_image, old_image)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stream_arn, shard_id, sequence) DO NOTHING;
-- name: AdvanceStreamTrimPoints :exec
-- Keep expiry selection on metadata ranges, not reverse scans of live payloads.
UPDATE dynamodb_stream_shards
SET trimmed_through = COALESCE((
 SELECT e.sequence FROM dynamodb_stream_entries AS e INDEXED BY dynamodb_stream_entries_shard_expiry
 WHERE e.stream_arn = dynamodb_stream_shards.stream_arn AND e.shard_id = dynamodb_stream_shards.shard_id
 AND e.created_at <= sqlc.arg(cutoff)
 AND (length(ltrim(e.sequence, '0')), ltrim(e.sequence, '0')) >
     (length(ltrim(dynamodb_stream_shards.trimmed_through, '0')), ltrim(dynamodb_stream_shards.trimmed_through, '0'))
 ORDER BY length(ltrim(e.sequence, '0')) DESC, ltrim(e.sequence, '0') DESC, e.sequence DESC
 LIMIT 1
), dynamodb_stream_shards.trimmed_through)
WHERE dynamodb_stream_shards.stream_arn = sqlc.arg(stream_arn)
AND dynamodb_stream_shards.shard_id IN (
 SELECT dynamodb_stream_entries.shard_id FROM dynamodb_stream_entries
 WHERE dynamodb_stream_entries.stream_arn = sqlc.arg(stream_arn) AND dynamodb_stream_entries.created_at <= sqlc.arg(cutoff)
);
-- name: DeleteExpiredStreamEntries :exec
DELETE FROM dynamodb_stream_entries WHERE stream_arn = sqlc.arg(stream_arn) AND created_at <= sqlc.arg(cutoff);
-- name: OldestStreamEntry :one
SELECT created_at FROM dynamodb_stream_entries WHERE stream_arn = ? ORDER BY created_at LIMIT 1;

-- name: GetTTLDeletion :one
SELECT * FROM dynamodb_ttl_deletions WHERE database_id = ?;
-- name: PutTTLDeletion :exec
INSERT INTO dynamodb_ttl_deletions (database_id, partition, account_id, region, table_name, physical_name, stream_arn, native_arn, keys_data, attribute_name, expiry, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
-- name: DeleteTTLDeletion :exec
DELETE FROM dynamodb_ttl_deletions WHERE database_id = ?;
