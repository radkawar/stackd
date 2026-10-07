-- name: PutStream :exec
INSERT INTO kinesis_streams (partition, account_id, region, name, engine_id, next_partition, retention_next_at, channel_count, consumer_count, encryption_type, key_id, max_record_size_kib, open_shard_count, retention_hours, stream_arn, created_at, stream_id, mode_present, mode, stream_name, status, warm_present, warm_current, warm_target, monitoring_present, shard_updates_present, encryption_updates_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(engine_id), sqlc.arg(next_partition), sqlc.arg(retention_next_at), sqlc.arg(channel_count), sqlc.arg(consumer_count), sqlc.arg(encryption_type), sqlc.arg(key_id), sqlc.arg(max_record_size_kib), sqlc.arg(open_shard_count), sqlc.arg(retention_hours), sqlc.arg(stream_arn), sqlc.arg(created_at), sqlc.arg(stream_id), sqlc.arg(mode_present), sqlc.arg(mode), sqlc.arg(stream_name), sqlc.arg(status), sqlc.arg(warm_present), sqlc.arg(warm_current), sqlc.arg(warm_target), sqlc.arg(monitoring_present), sqlc.arg(shard_updates_present), sqlc.arg(encryption_updates_present))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET engine_id = excluded.engine_id, next_partition = excluded.next_partition, retention_next_at = excluded.retention_next_at, channel_count = excluded.channel_count, consumer_count = excluded.consumer_count, encryption_type = excluded.encryption_type, key_id = excluded.key_id, max_record_size_kib = excluded.max_record_size_kib, open_shard_count = excluded.open_shard_count, retention_hours = excluded.retention_hours, stream_arn = excluded.stream_arn, created_at = excluded.created_at, stream_id = excluded.stream_id, mode_present = excluded.mode_present, mode = excluded.mode, stream_name = excluded.stream_name, status = excluded.status, warm_present = excluded.warm_present, warm_current = excluded.warm_current, warm_target = excluded.warm_target, monitoring_present = excluded.monitoring_present, shard_updates_present = excluded.shard_updates_present, encryption_updates_present = excluded.encryption_updates_present;

-- name: GetStream :one
SELECT * FROM kinesis_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: DeleteStream :exec
DELETE FROM kinesis_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutPendingUpdate :exec
INSERT INTO kinesis_pending_updates (partition, account_id, region, name, accepted_at, retention_hours, mode, max_record_size_kib, encryption_type, key_id, monitoring_present, warm_mibps, peak_shard_count)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(accepted_at), sqlc.arg(retention_hours), sqlc.arg(mode), sqlc.arg(max_record_size_kib), sqlc.arg(encryption_type), sqlc.arg(key_id), sqlc.arg(monitoring_present), sqlc.arg(warm_mibps), sqlc.arg(peak_shard_count))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET accepted_at = excluded.accepted_at, retention_hours = excluded.retention_hours, mode = excluded.mode, max_record_size_kib = excluded.max_record_size_kib, encryption_type = excluded.encryption_type, key_id = excluded.key_id, monitoring_present = excluded.monitoring_present, warm_mibps = excluded.warm_mibps, peak_shard_count = excluded.peak_shard_count;

-- name: GetPendingUpdate :one
SELECT * FROM kinesis_pending_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: DeletePendingUpdate :exec
DELETE FROM kinesis_pending_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutMonitoringGroup :exec
INSERT INTO kinesis_monitoring_groups (partition, account_id, region, name, position, metrics_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(position), sqlc.arg(metrics_present))
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET metrics_present = excluded.metrics_present;

-- name: ListMonitoringGroups :many
SELECT * FROM kinesis_monitoring_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY position;

-- name: DeleteMonitoringGroups :exec
DELETE FROM kinesis_monitoring_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutMonitoringMetric :exec
INSERT INTO kinesis_monitoring_metrics (partition, account_id, region, name, group_position, position, metric)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(group_position), sqlc.arg(position), sqlc.arg(metric))
ON CONFLICT (partition, account_id, region, name, group_position, position) DO UPDATE SET metric = excluded.metric;

-- name: ListMonitoringMetrics :many
SELECT * FROM kinesis_monitoring_metrics WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY group_position, position;

-- name: DeleteMonitoringMetrics :exec
DELETE FROM kinesis_monitoring_metrics WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutPendingMetric :exec
INSERT INTO kinesis_pending_metrics (partition, account_id, region, name, position, metric)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(position), sqlc.arg(metric))
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET metric = excluded.metric;

-- name: ListPendingMetrics :many
SELECT * FROM kinesis_pending_metrics WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY position;

-- name: DeletePendingMetrics :exec
DELETE FROM kinesis_pending_metrics WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutShardUpdate :exec
INSERT INTO kinesis_shard_updates (partition, account_id, region, name, position, at)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(position), sqlc.arg(at))
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET at = excluded.at;

-- name: ListShardUpdates :many
SELECT * FROM kinesis_shard_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY position;

-- name: DeleteShardUpdates :exec
DELETE FROM kinesis_shard_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutEncryptionUpdate :exec
INSERT INTO kinesis_encryption_updates (partition, account_id, region, name, position, at, enabled)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(position), sqlc.arg(at), sqlc.arg(enabled))
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET at = excluded.at, enabled = excluded.enabled;

-- name: ListEncryptionUpdates :many
SELECT * FROM kinesis_encryption_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY position;

-- name: DeleteEncryptionUpdates :exec
DELETE FROM kinesis_encryption_updates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: PutShard :exec
INSERT INTO kinesis_shards (partition, account_id, region, name, native_partition, state, opened_at, closed_at, shard_id, parent_id, adjacent_parent_id, hash_present, hash_start, hash_end, sequence_present, sequence_start, sequence_end)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(native_partition), sqlc.arg(state), sqlc.arg(opened_at), sqlc.arg(closed_at), sqlc.arg(shard_id), sqlc.arg(parent_id), sqlc.arg(adjacent_parent_id), sqlc.arg(hash_present), sqlc.arg(hash_start), sqlc.arg(hash_end), sqlc.arg(sequence_present), sqlc.arg(sequence_start), sqlc.arg(sequence_end))
ON CONFLICT (partition, account_id, region, name, native_partition) DO UPDATE SET state = excluded.state, opened_at = excluded.opened_at, closed_at = excluded.closed_at, shard_id = excluded.shard_id, parent_id = excluded.parent_id, adjacent_parent_id = excluded.adjacent_parent_id, hash_present = excluded.hash_present, hash_start = excluded.hash_start, hash_end = excluded.hash_end, sequence_present = excluded.sequence_present, sequence_start = excluded.sequence_start, sequence_end = excluded.sequence_end;

-- name: ListShards :many
SELECT * FROM kinesis_shards WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY native_partition;


-- name: PutConsumer :exec
INSERT INTO kinesis_consumers (partition, account_id, region, name, consumer_name, created_at, consumer_arn, creation_timestamp, data_name, status, stream_arn, delete_at)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(consumer_name), sqlc.arg(created_at), sqlc.arg(consumer_arn), sqlc.arg(creation_timestamp), sqlc.arg(data_name), sqlc.arg(status), sqlc.arg(stream_arn), sqlc.arg(delete_at))
ON CONFLICT (partition, account_id, region, name, consumer_name, created_at) DO UPDATE SET consumer_arn = excluded.consumer_arn, creation_timestamp = excluded.creation_timestamp, data_name = excluded.data_name, status = excluded.status, stream_arn = excluded.stream_arn, delete_at = excluded.delete_at;

-- name: GetConsumer :one
SELECT * FROM kinesis_consumers WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND consumer_name = sqlc.arg(consumer_name) AND created_at = sqlc.arg(created_at);

-- name: ListConsumers :many
SELECT * FROM kinesis_consumers WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY consumer_name, created_at;

-- name: DeleteConsumer :exec
DELETE FROM kinesis_consumers WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND consumer_name = sqlc.arg(consumer_name) AND created_at = sqlc.arg(created_at);

-- name: PutTagSet :exec
INSERT INTO kinesis_tag_sets (partition, account_id, region, arn, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(tags_present))
ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET tags_present = excluded.tags_present;

-- name: GetTagSet :one
SELECT * FROM kinesis_tag_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: DeleteTagSet :exec
DELETE FROM kinesis_tag_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: PutTag :exec
INSERT INTO kinesis_tags (partition, account_id, region, arn, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, arn, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: ListTags :many
SELECT * FROM kinesis_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) ORDER BY position;

-- name: DeleteTags :exec
DELETE FROM kinesis_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: PutPolicy :exec
INSERT INTO kinesis_policies (partition, account_id, region, arn, document, trust_policy, principals_present, effective_document, effective_trust_policy, effective_principals_present, publish_at)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(document), sqlc.arg(trust_policy), sqlc.arg(principals_present), sqlc.arg(effective_document), sqlc.arg(effective_trust_policy), sqlc.arg(effective_principals_present), sqlc.arg(publish_at))
ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET document = excluded.document, trust_policy = excluded.trust_policy, principals_present = excluded.principals_present, effective_document = excluded.effective_document, effective_trust_policy = excluded.effective_trust_policy, effective_principals_present = excluded.effective_principals_present, publish_at = excluded.publish_at;

-- name: GetPolicy :one
SELECT * FROM kinesis_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: DeletePolicy :exec
DELETE FROM kinesis_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: PutPolicyPrincipal :exec
INSERT INTO kinesis_policy_principals (partition, account_id, region, arn, effective, principal, principal_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(effective), sqlc.arg(principal), sqlc.arg(principal_id))
ON CONFLICT (partition, account_id, region, arn, effective, principal) DO UPDATE SET principal_id = excluded.principal_id;

-- name: ListPolicyPrincipals :many
SELECT * FROM kinesis_policy_principals WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) ORDER BY effective, principal;

-- name: DeletePolicyPrincipals :exec
DELETE FROM kinesis_policy_principals WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);

-- name: PutAccount :exec
INSERT INTO kinesis_accounts (partition, account_id, region, earliest_allowed_end_at, ended_at, started_at, status)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(earliest_allowed_end_at), sqlc.arg(ended_at), sqlc.arg(started_at), sqlc.arg(status))
ON CONFLICT (partition, account_id, region) DO UPDATE SET earliest_allowed_end_at = excluded.earliest_allowed_end_at, ended_at = excluded.ended_at, started_at = excluded.started_at, status = excluded.status;

-- name: GetAccount :one
SELECT * FROM kinesis_accounts WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region);


-- name: PutModeSwitchSet :exec
INSERT INTO kinesis_mode_switch_sets (partition, account_id, region, name, times_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(times_present))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET times_present = excluded.times_present;

-- name: GetModeSwitchSet :one
SELECT * FROM kinesis_mode_switch_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);


-- name: PutModeSwitch :exec
INSERT INTO kinesis_mode_switches (partition, account_id, region, name, position, at)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(position), sqlc.arg(at))
ON CONFLICT (partition, account_id, region, name, position) DO UPDATE SET at = excluded.at;

-- name: ListModeSwitches :many
SELECT * FROM kinesis_mode_switches WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY position;

-- name: DeleteModeSwitches :exec
DELETE FROM kinesis_mode_switches WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: AddMetricSample :exec
INSERT INTO kinesis_metric_samples (partition, account_id, region, name, minute, consumer_name, shard_id, metric_name, value, sample_count)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(minute), sqlc.arg(consumer_name), sqlc.arg(shard_id), sqlc.arg(metric_name), sqlc.arg(value), sqlc.arg(sample_count))
ON CONFLICT (partition, account_id, region, name, minute, consumer_name, shard_id, metric_name, value) DO UPDATE SET sample_count = sample_count + excluded.sample_count;

-- name: ListMetricSamples :many
SELECT * FROM kinesis_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND minute = sqlc.arg(minute) ORDER BY consumer_name, shard_id, metric_name, value;

-- name: DeleteMetricSamples :exec
DELETE FROM kinesis_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND minute = sqlc.arg(minute);

-- name: ListStreams :many
SELECT * FROM kinesis_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name > sqlc.arg(after_name) ORDER BY name LIMIT sqlc.arg(row_limit);

-- name: AllStreams :many
SELECT * FROM kinesis_streams ORDER BY partition, account_id, region, name;

-- name: NextMetricPublication :one
SELECT partition, account_id, region, name, minute FROM kinesis_metric_samples ORDER BY minute, partition, account_id, region, name LIMIT 1;

-- name: SetStreamOwner :exec
UPDATE kinesis_streams SET owner_stack_id = sqlc.arg(owner_stack_id), owner_logical_id = sqlc.arg(owner_logical_id), owner_token = sqlc.arg(owner_token)
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: SetConsumerOwner :exec
UPDATE kinesis_consumers SET owner_stack_id = sqlc.arg(owner_stack_id), owner_logical_id = sqlc.arg(owner_logical_id), owner_token = sqlc.arg(owner_token)
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND consumer_name = sqlc.arg(consumer_name) AND created_at = sqlc.arg(created_at);

-- name: SetPolicyOwner :exec
UPDATE kinesis_policies SET owner_stack_id = sqlc.arg(owner_stack_id), owner_logical_id = sqlc.arg(owner_logical_id), owner_token = sqlc.arg(owner_token)
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
