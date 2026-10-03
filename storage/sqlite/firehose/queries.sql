-- name: PutStream :exec
INSERT INTO firehose_streams (id, partition, account_id, region, name, status, version, created, updated, lifecycle_due, buffer_id, tags_present)
VALUES (sqlc.arg(id), sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(status), sqlc.arg(version), sqlc.arg(created), sqlc.arg(updated), sqlc.arg(lifecycle_due), sqlc.arg(buffer_id), sqlc.arg(tags_present))
ON CONFLICT (id) DO UPDATE SET partition = excluded.partition, account_id = excluded.account_id, region = excluded.region, name = excluded.name, status = excluded.status, version = excluded.version, created = excluded.created, updated = excluded.updated, lifecycle_due = excluded.lifecycle_due, buffer_id = excluded.buffer_id, tags_present = excluded.tags_present;

-- name: PutSource :exec
INSERT INTO firehose_sources (stream_id, arn, role_arn, created, delivery_start, due, retention_hours)
VALUES (sqlc.arg(stream_id), sqlc.arg(arn), sqlc.arg(role_arn), sqlc.arg(created), sqlc.arg(delivery_start), sqlc.arg(due), sqlc.arg(retention_hours))
ON CONFLICT (stream_id) DO UPDATE SET arn = excluded.arn, role_arn = excluded.role_arn, created = excluded.created, delivery_start = excluded.delivery_start, due = excluded.due, retention_hours = excluded.retention_hours;

-- name: PutTag :exec
INSERT INTO firehose_tags (stream_id, key, value)
VALUES (sqlc.arg(stream_id), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (stream_id, key) DO UPDATE SET value = excluded.value;

-- name: PutBuffer :exec
INSERT INTO firehose_buffers (id, stream_id, partition, account_id, region, name, created, due, count, bytes, parent_event_id, object_key, stream_version, kind)
VALUES (sqlc.arg(id), sqlc.arg(stream_id), sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(created), sqlc.arg(due), sqlc.arg(count), sqlc.arg(bytes), sqlc.arg(parent_event_id), sqlc.arg(object_key), sqlc.arg(stream_version), sqlc.arg(kind))
ON CONFLICT (id) DO UPDATE SET stream_id = excluded.stream_id, partition = excluded.partition, account_id = excluded.account_id, region = excluded.region, name = excluded.name, created = excluded.created, due = excluded.due, count = excluded.count, bytes = excluded.bytes, parent_event_id = excluded.parent_event_id, object_key = excluded.object_key, stream_version = excluded.stream_version, kind = excluded.kind;

-- name: PutConfiguration :exec
INSERT INTO firehose_configurations (id, stream_id, buffer_id, bucket_arn, role_arn, prefix, error_output_prefix, compression_format, custom_time_zone, file_extension, backup_mode, buffering_present, interval_seconds, size_mbs, logging_present, logging_enabled, log_group, log_stream, encryption_present, no_encryption, processing_present, processing_enabled, processors_present, parent_configuration_id, kms_key_arn)
VALUES (sqlc.arg(id), sqlc.arg(stream_id), sqlc.arg(buffer_id), sqlc.arg(bucket_arn), sqlc.arg(role_arn), sqlc.arg(prefix), sqlc.arg(error_output_prefix), sqlc.arg(compression_format), sqlc.arg(custom_time_zone), sqlc.arg(file_extension), sqlc.arg(backup_mode), sqlc.arg(buffering_present), sqlc.arg(interval_seconds), sqlc.arg(size_mbs), sqlc.arg(logging_present), sqlc.arg(logging_enabled), sqlc.arg(log_group), sqlc.arg(log_stream), sqlc.arg(encryption_present), sqlc.arg(no_encryption), sqlc.arg(processing_present), sqlc.arg(processing_enabled), sqlc.arg(processors_present), sqlc.arg(parent_configuration_id), sqlc.arg(kms_key_arn))
ON CONFLICT (id) DO UPDATE SET stream_id = excluded.stream_id, buffer_id = excluded.buffer_id, bucket_arn = excluded.bucket_arn, role_arn = excluded.role_arn, prefix = excluded.prefix, error_output_prefix = excluded.error_output_prefix, compression_format = excluded.compression_format, custom_time_zone = excluded.custom_time_zone, file_extension = excluded.file_extension, backup_mode = excluded.backup_mode, buffering_present = excluded.buffering_present, interval_seconds = excluded.interval_seconds, size_mbs = excluded.size_mbs, logging_present = excluded.logging_present, logging_enabled = excluded.logging_enabled, log_group = excluded.log_group, log_stream = excluded.log_stream, encryption_present = excluded.encryption_present, no_encryption = excluded.no_encryption, processing_present = excluded.processing_present, processing_enabled = excluded.processing_enabled, processors_present = excluded.processors_present, parent_configuration_id = excluded.parent_configuration_id, kms_key_arn = excluded.kms_key_arn;

-- name: PutProcessor :exec
INSERT INTO firehose_processors (configuration_id, position, type, parameters_present)
VALUES (sqlc.arg(configuration_id), sqlc.arg(position), sqlc.arg(type), sqlc.arg(parameters_present))
ON CONFLICT (configuration_id, position) DO UPDATE SET type = excluded.type, parameters_present = excluded.parameters_present;

-- name: PutProcessorParameter :exec
INSERT INTO firehose_processor_parameters (configuration_id, processor_position, position, name, value)
VALUES (sqlc.arg(configuration_id), sqlc.arg(processor_position), sqlc.arg(position), sqlc.arg(name), sqlc.arg(value))
ON CONFLICT (configuration_id, processor_position, position) DO UPDATE SET name = excluded.name, value = excluded.value;

-- name: PutRecord :exec
INSERT INTO firehose_records (buffer_id, position, data, arrived, original_bytes, kinesis_shard_id, kinesis_partition_key, kinesis_sequence_number, kinesis_subsequence_number)
VALUES (sqlc.arg(buffer_id), sqlc.arg(position), sqlc.arg(data), sqlc.arg(arrived), sqlc.arg(original_bytes), sqlc.arg(kinesis_shard_id), sqlc.arg(kinesis_partition_key), sqlc.arg(kinesis_sequence_number), sqlc.arg(kinesis_subsequence_number))
ON CONFLICT (buffer_id, position) DO UPDATE SET data = excluded.data, arrived = excluded.arrived, original_bytes = excluded.original_bytes, kinesis_shard_id = excluded.kinesis_shard_id, kinesis_partition_key = excluded.kinesis_partition_key, kinesis_sequence_number = excluded.kinesis_sequence_number, kinesis_subsequence_number = excluded.kinesis_subsequence_number;

-- name: PutProcessing :exec
INSERT INTO firehose_processing (buffer_id, state, attempts, due)
VALUES (sqlc.arg(buffer_id), sqlc.arg(state), sqlc.arg(attempts), sqlc.arg(due))
ON CONFLICT (buffer_id) DO UPDATE SET state = excluded.state, attempts = excluded.attempts, due = excluded.due;

-- name: PutCheckpoint :exec
INSERT INTO firehose_checkpoints (stream_id, shard_id, sequence, closed)
VALUES (sqlc.arg(stream_id), sqlc.arg(shard_id), sqlc.arg(sequence), sqlc.arg(closed))
ON CONFLICT (stream_id, shard_id) DO UPDATE SET sequence = excluded.sequence, closed = excluded.closed;

-- name: PutMetricSample :exec
INSERT INTO firehose_metric_samples (partition, account_id, region, name, minute, metric_name, value, sample_count)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(minute), sqlc.arg(metric_name), sqlc.arg(value), sqlc.arg(sample_count))
ON CONFLICT (partition, account_id, region, name, minute, metric_name, value) DO UPDATE SET sample_count = firehose_metric_samples.sample_count + excluded.sample_count;

-- name: GetStream :one
SELECT * FROM firehose_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: GetStreamByID :one
SELECT * FROM firehose_streams WHERE id = ?;

-- name: DeleteStream :exec
DELETE FROM firehose_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: ListStreams :many
SELECT * FROM firehose_streams WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name > sqlc.arg(after_name) AND (sqlc.arg(stream_type) = '' OR CASE WHEN EXISTS (SELECT 1 FROM firehose_sources WHERE stream_id = firehose_streams.id) THEN 'KinesisStreamAsSource' ELSE 'DirectPut' END = sqlc.arg(stream_type)) ORDER BY name LIMIT sqlc.arg(row_limit);

-- name: NextLifecycle :one
SELECT * FROM firehose_streams WHERE status IN ('CREATING', 'DELETING') ORDER BY lifecycle_due, id LIMIT 1;

-- name: NextSource :one
SELECT firehose_streams.* FROM firehose_streams JOIN firehose_sources ON firehose_sources.stream_id = firehose_streams.id WHERE status = 'ACTIVE' ORDER BY firehose_sources.due, firehose_streams.id LIMIT 1;

-- name: GetSource :one
SELECT * FROM firehose_sources WHERE stream_id = ?;

-- name: DeleteSource :exec
DELETE FROM firehose_sources WHERE stream_id = ?;

-- name: GetBuffer :one
SELECT * FROM firehose_buffers WHERE id = ?;

-- name: OpenOutputBuffer :one
SELECT * FROM firehose_buffers WHERE stream_id = sqlc.arg(stream_id) AND stream_version = sqlc.arg(stream_version) AND kind = sqlc.arg(kind) AND object_key = '' ORDER BY created, id LIMIT 1;

-- name: DeleteBuffer :exec
DELETE FROM firehose_buffers WHERE id = ?;

-- name: GetConfiguration :one
SELECT * FROM firehose_configurations WHERE id = ?;

-- name: GetBackupConfiguration :one
SELECT * FROM firehose_configurations WHERE parent_configuration_id = ?;

-- name: DeleteBackupConfiguration :exec
DELETE FROM firehose_configurations WHERE parent_configuration_id = ?;

-- name: DeleteConfiguration :exec
DELETE FROM firehose_configurations WHERE id = ?;

-- name: NextDelivery :one
SELECT * FROM firehose_buffers WHERE NOT EXISTS (SELECT 1 FROM firehose_processing WHERE buffer_id = firehose_buffers.id) ORDER BY due, id LIMIT 1;

-- name: GetProcessing :one
SELECT * FROM firehose_processing WHERE buffer_id = ?;

-- name: NextProcessing :one
SELECT * FROM firehose_processing WHERE state = 'queued' ORDER BY due, buffer_id LIMIT 1;

-- name: InFlightProcessing :many
SELECT * FROM firehose_processing WHERE state = 'in-flight' ORDER BY buffer_id;

-- name: ListTags :many
SELECT * FROM firehose_tags WHERE stream_id = ? ORDER BY key;

-- name: ListRecords :many
SELECT * FROM firehose_records WHERE buffer_id = ? ORDER BY position;

-- name: ListCheckpoints :many
SELECT * FROM firehose_checkpoints WHERE stream_id = ? ORDER BY shard_id;

-- name: ListProcessors :many
SELECT * FROM firehose_processors WHERE configuration_id = ? ORDER BY position;

-- name: ListProcessorParameters :many
SELECT * FROM firehose_processor_parameters WHERE configuration_id = ? ORDER BY processor_position, position;

-- name: DeleteTags :exec
DELETE FROM firehose_tags WHERE stream_id = ?;

-- name: DeleteProcessors :exec
DELETE FROM firehose_processors WHERE configuration_id = ?;

-- name: NextMetricPublication :one
SELECT partition, account_id, region, name, minute FROM firehose_metric_samples ORDER BY minute, partition, account_id, region, name LIMIT 1;

-- name: ListMetricSamples :many
SELECT metric_name, value, sample_count FROM firehose_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND minute = sqlc.arg(minute) ORDER BY metric_name, value;

-- name: DeleteMetricPublication :exec
DELETE FROM firehose_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND minute = sqlc.arg(minute);
