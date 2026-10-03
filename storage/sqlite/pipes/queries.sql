-- name: PutPipe :exec
INSERT INTO pipes_pipes (partition, account_id, region, name, id, version, description, role_arn, source_arn, target_arn, enrichment_arn, state, desired, reason, created_ns, modified_ns, due_ns, source_kind, starting_position, starting_time_ns, batch_size, window_seconds, maximum_age, maximum_retries, parallelism, automatic_bisect, dlq_arn, enrichment_template, parent_event_id, target_template, target_group_id, target_deduplication_id, target_partition_key, target_lambda_invocation, target_states_invocation, target_log_stream, target_log_timestamp, target_event_source, target_event_detail_type, target_event_time, target_event_endpoint, target_ecs_task_definition, target_ecs_task_count, target_ecs_launch_type, target_ecs_group, target_ecs_platform_version, target_ecs_propagate_tags, target_ecs_reference_id, target_ecs_enable_managed_tags, target_ecs_enable_execute_command, target_ecs_capacity_strategy, target_ecs_network, target_ecs_overrides, target_ecs_placement_constraints, target_ecs_placement_strategy, target_ecs_tags, target_http_present, target_http_headers, target_http_paths, target_http_query, enrichment_http_present, enrichment_http_headers, enrichment_http_paths, enrichment_http_query)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET id=excluded.id, version=excluded.version, description=excluded.description, role_arn=excluded.role_arn, source_arn=excluded.source_arn, target_arn=excluded.target_arn, enrichment_arn=excluded.enrichment_arn, state=excluded.state, desired=excluded.desired, reason=excluded.reason, created_ns=excluded.created_ns, modified_ns=excluded.modified_ns, due_ns=excluded.due_ns, source_kind=excluded.source_kind, starting_position=excluded.starting_position, starting_time_ns=excluded.starting_time_ns, batch_size=excluded.batch_size, window_seconds=excluded.window_seconds, maximum_age=excluded.maximum_age, maximum_retries=excluded.maximum_retries, parallelism=excluded.parallelism, automatic_bisect=excluded.automatic_bisect, dlq_arn=excluded.dlq_arn, enrichment_template=excluded.enrichment_template, parent_event_id=excluded.parent_event_id, target_template=excluded.target_template, target_group_id=excluded.target_group_id, target_deduplication_id=excluded.target_deduplication_id, target_partition_key=excluded.target_partition_key, target_lambda_invocation=excluded.target_lambda_invocation, target_states_invocation=excluded.target_states_invocation, target_log_stream=excluded.target_log_stream, target_log_timestamp=excluded.target_log_timestamp, target_event_source=excluded.target_event_source, target_event_detail_type=excluded.target_event_detail_type, target_event_time=excluded.target_event_time, target_event_endpoint=excluded.target_event_endpoint, target_ecs_task_definition=excluded.target_ecs_task_definition, target_ecs_task_count=excluded.target_ecs_task_count, target_ecs_launch_type=excluded.target_ecs_launch_type, target_ecs_group=excluded.target_ecs_group, target_ecs_platform_version=excluded.target_ecs_platform_version, target_ecs_propagate_tags=excluded.target_ecs_propagate_tags, target_ecs_reference_id=excluded.target_ecs_reference_id, target_ecs_enable_managed_tags=excluded.target_ecs_enable_managed_tags, target_ecs_enable_execute_command=excluded.target_ecs_enable_execute_command, target_ecs_capacity_strategy=excluded.target_ecs_capacity_strategy, target_ecs_network=excluded.target_ecs_network, target_ecs_overrides=excluded.target_ecs_overrides, target_ecs_placement_constraints=excluded.target_ecs_placement_constraints, target_ecs_placement_strategy=excluded.target_ecs_placement_strategy, target_ecs_tags=excluded.target_ecs_tags, target_http_present=excluded.target_http_present, target_http_headers=excluded.target_http_headers, target_http_paths=excluded.target_http_paths, target_http_query=excluded.target_http_query, enrichment_http_present=excluded.enrichment_http_present, enrichment_http_headers=excluded.enrichment_http_headers, enrichment_http_paths=excluded.enrichment_http_paths, enrichment_http_query=excluded.enrichment_http_query;

-- name: PutTag :exec
INSERT INTO pipes_tags (pipe_id, key, value)
VALUES (?, ?, ?)
ON CONFLICT (pipe_id, key) DO UPDATE SET value=excluded.value;

-- name: PutFilter :exec
INSERT INTO pipes_filters (pipe_id, position, pattern)
VALUES (?, ?, ?)
ON CONFLICT (pipe_id, position) DO UPDATE SET pattern=excluded.pattern;

-- name: PutEventResource :exec
INSERT INTO pipes_target_event_resources (pipe_id, position, arn)
VALUES (?, ?, ?)
ON CONFLICT (pipe_id, position) DO UPDATE SET arn=excluded.arn;

-- name: PutCheckpoint :exec
INSERT INTO pipes_checkpoints (pipe_id, shard_id, parent_id, adjacent_parent_id, sequence, iterator, initialized, closed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (pipe_id, shard_id) DO UPDATE SET parent_id=excluded.parent_id, adjacent_parent_id=excluded.adjacent_parent_id, sequence=excluded.sequence, iterator=excluded.iterator, initialized=excluded.initialized, closed=excluded.closed;

-- name: PutWork :exec
INSERT INTO pipes_work (id, pipe_id, shard_id, record_id, sequence, receipt, group_id, ordinal, event, created_ns, due_ns, attempts, batch_limit, phase, last_error, filtered)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET pipe_id=excluded.pipe_id, shard_id=excluded.shard_id, record_id=excluded.record_id, sequence=excluded.sequence, receipt=excluded.receipt, group_id=excluded.group_id, ordinal=excluded.ordinal, event=excluded.event, created_ns=excluded.created_ns, due_ns=excluded.due_ns, attempts=excluded.attempts, batch_limit=excluded.batch_limit, phase=excluded.phase, last_error=excluded.last_error, filtered=excluded.filtered;

-- name: Pipe :one
SELECT * FROM pipes_pipes WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: PipeByID :one
SELECT * FROM pipes_pipes WHERE id=?;
-- name: Pipes :many
SELECT * FROM pipes_pipes ORDER BY partition,account_id,region,name;
-- name: DeletePipe :exec
DELETE FROM pipes_pipes WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: Tags :many
SELECT * FROM pipes_tags WHERE pipe_id=? ORDER BY key;
-- name: DeleteTags :exec
DELETE FROM pipes_tags WHERE pipe_id=?;
-- name: Filters :many
SELECT * FROM pipes_filters WHERE pipe_id=? ORDER BY position;
-- name: DeleteFilters :exec
DELETE FROM pipes_filters WHERE pipe_id=?;
-- name: EventResources :many
SELECT * FROM pipes_target_event_resources WHERE pipe_id=? ORDER BY position;
-- name: DeleteEventResources :exec
DELETE FROM pipes_target_event_resources WHERE pipe_id=?;
-- name: Checkpoints :many
SELECT * FROM pipes_checkpoints WHERE pipe_id=? ORDER BY shard_id;
-- name: Work :many
SELECT * FROM pipes_work WHERE pipe_id=? ORDER BY ordinal,id;
-- name: DeleteWork :exec
DELETE FROM pipes_work WHERE id=?;

-- name: Encryption :one
SELECT * FROM pipes_encryption WHERE pipe_id=?;
-- name: PutEncryption :exec
INSERT INTO pipes_encryption(pipe_id,key_arn,wrapped_key,nonce,ciphertext)
VALUES (?,?,?,?,?)
ON CONFLICT(pipe_id) DO UPDATE SET key_arn=excluded.key_arn,wrapped_key=excluded.wrapped_key,nonce=excluded.nonce,ciphertext=excluded.ciphertext;
-- name: DeleteEncryption :exec
DELETE FROM pipes_encryption WHERE pipe_id=?;

-- name: Logging :one
SELECT * FROM pipes_logging WHERE pipe_id=?;
-- name: PutLogging :exec
INSERT INTO pipes_logging(pipe_id,level,include_execution_data,log_group_arn,firehose_arn,bucket_name,bucket_owner,prefix,output_format)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT(pipe_id) DO UPDATE SET level=excluded.level,include_execution_data=excluded.include_execution_data,log_group_arn=excluded.log_group_arn,firehose_arn=excluded.firehose_arn,bucket_name=excluded.bucket_name,bucket_owner=excluded.bucket_owner,prefix=excluded.prefix,output_format=excluded.output_format;

-- name: KafkaSource :one
SELECT * FROM pipes_kafka_sources WHERE pipe_id=?;
-- name: PutKafkaSource :exec
INSERT INTO pipes_kafka_sources(pipe_id,topic,consumer_group_id,authentication,secret_arn,root_ca_secret_arn)
VALUES (?,?,?,?,?,?)
ON CONFLICT(pipe_id) DO UPDATE SET topic=excluded.topic,consumer_group_id=excluded.consumer_group_id,authentication=excluded.authentication,secret_arn=excluded.secret_arn,root_ca_secret_arn=excluded.root_ca_secret_arn;
-- name: KafkaBootstrapServers :many
SELECT * FROM pipes_kafka_bootstrap_servers WHERE pipe_id=? ORDER BY position;
-- name: DeleteKafkaBootstrapServers :exec
DELETE FROM pipes_kafka_bootstrap_servers WHERE pipe_id=?;
-- name: PutKafkaBootstrapServer :exec
INSERT INTO pipes_kafka_bootstrap_servers(pipe_id,position,address) VALUES (?,?,?);

-- name: KafkaIdentity :one
SELECT * FROM pipes_kafka_identities WHERE pipe_id=?;
-- name: PutKafkaIdentity :exec
INSERT INTO pipes_kafka_identities(pipe_id,cluster_id,topic_id) VALUES (?,?,?)
ON CONFLICT(pipe_id) DO NOTHING;
