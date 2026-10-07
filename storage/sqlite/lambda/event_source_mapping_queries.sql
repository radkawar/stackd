-- name: GetEventSourceMapping :one
SELECT * FROM lambda_event_source_mappings WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: ListEventSourceMappings :many
SELECT * FROM lambda_event_source_mappings WHERE partition=? AND account=? AND region=? ORDER BY uuid;

-- name: AllEventSourceMappings :many
SELECT * FROM lambda_event_source_mappings ORDER BY partition,region,account,uuid;

-- name: PutEventSourceMapping :exec
INSERT INTO lambda_event_source_mappings(partition,account,region,uuid,function_partition,function_account,function_region,function_name,function_qualifier,event_source_arn,version,state,state_transition_reason,last_modified,transition_at,batch_size,batching_window_seconds,report_batch_item_failures,maximum_concurrency,minimum_pollers,maximum_pollers,transition_state,last_processing_result,stream_starting_position,stream_starting_position_timestamp,stream_parallelization_factor,stream_maximum_retry_attempts,stream_maximum_record_age_seconds,stream_bisect_batch_on_function_error,stream_tumbling_window_seconds,stream_on_failure,owner_stack_id,owner_logical_id,owner_token)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET function_partition=excluded.function_partition,function_account=excluded.function_account,function_region=excluded.function_region,function_name=excluded.function_name,function_qualifier=excluded.function_qualifier,event_source_arn=excluded.event_source_arn,version=excluded.version,state=excluded.state,state_transition_reason=excluded.state_transition_reason,last_modified=excluded.last_modified,transition_at=excluded.transition_at,batch_size=excluded.batch_size,batching_window_seconds=excluded.batching_window_seconds,report_batch_item_failures=excluded.report_batch_item_failures,maximum_concurrency=excluded.maximum_concurrency,minimum_pollers=excluded.minimum_pollers,maximum_pollers=excluded.maximum_pollers,transition_state=excluded.transition_state,stream_starting_position=excluded.stream_starting_position,stream_starting_position_timestamp=excluded.stream_starting_position_timestamp,stream_parallelization_factor=excluded.stream_parallelization_factor,stream_maximum_retry_attempts=excluded.stream_maximum_retry_attempts,stream_maximum_record_age_seconds=excluded.stream_maximum_record_age_seconds,stream_bisect_batch_on_function_error=excluded.stream_bisect_batch_on_function_error,stream_tumbling_window_seconds=excluded.stream_tumbling_window_seconds,stream_on_failure=excluded.stream_on_failure,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;

-- name: DeleteEventSourceMapping :exec
DELETE FROM lambda_event_source_mappings WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: SetEventSourceMappingProcessingResult :execrows
UPDATE lambda_event_source_mappings SET last_processing_result=? WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: ListEventSourceMappingFilters :many
SELECT pattern FROM lambda_event_source_mapping_filters WHERE partition=? AND account=? AND region=? AND uuid=? ORDER BY position;

-- name: DeleteEventSourceMappingFilters :exec
DELETE FROM lambda_event_source_mapping_filters WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutEventSourceMappingFilter :exec
INSERT INTO lambda_event_source_mapping_filters(partition,account,region,uuid,position,pattern) VALUES(?,?,?,?,?,?);

-- name: ListEventSourceMappingMetrics :many
SELECT metric FROM lambda_event_source_mapping_metrics WHERE partition=? AND account=? AND region=? AND uuid=? ORDER BY position;

-- name: DeleteEventSourceMappingMetrics :exec
DELETE FROM lambda_event_source_mapping_metrics WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutEventSourceMappingMetric :exec
INSERT INTO lambda_event_source_mapping_metrics(partition,account,region,uuid,position,metric) VALUES(?,?,?,?,?,?);

-- name: ListEventSourceMappingTags :many
SELECT key,value FROM lambda_event_source_mapping_tags WHERE partition=? AND account=? AND region=? AND uuid=? ORDER BY key;

-- name: DeleteEventSourceMappingTags :exec
DELETE FROM lambda_event_source_mapping_tags WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutEventSourceMappingTag :exec
INSERT INTO lambda_event_source_mapping_tags(partition,account,region,uuid,key,value) VALUES(?,?,?,?,?,?);

-- name: GetEventSourceFilterEncryption :one
SELECT * FROM lambda_event_source_filter_encryption WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: DeleteEventSourceFilterEncryption :exec
DELETE FROM lambda_event_source_filter_encryption WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutEventSourceFilterEncryption :exec
INSERT INTO lambda_event_source_filter_encryption(partition,account,region,uuid,key_arn,function_arn,content,data_key,format)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET key_arn=excluded.key_arn,function_arn=excluded.function_arn,content=excluded.content,data_key=excluded.data_key,format=excluded.format;
