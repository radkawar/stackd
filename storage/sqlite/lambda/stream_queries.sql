-- name: ListStreamShards :many
SELECT * FROM lambda_stream_shards WHERE mapping_arn=? ORDER BY shard_id;
-- name: PutStreamShard :execrows
INSERT INTO lambda_stream_shards(mapping_arn,shard_id,parent_id,adjacent_parent_id,starting_position_timestamp,retention_nanoseconds,checkpoint,read_complete,complete)
SELECT sqlc.arg(mapping_arn),sqlc.arg(shard_id),sqlc.arg(parent_id),sqlc.arg(adjacent_parent_id),sqlc.arg(starting_position_timestamp),sqlc.arg(retention_nanoseconds),sqlc.arg(checkpoint),sqlc.arg(read_complete),sqlc.arg(complete)
WHERE EXISTS (SELECT 1 FROM lambda_event_source_mappings WHERE partition=sqlc.arg(partition) AND account=sqlc.arg(account) AND region=sqlc.arg(region) AND uuid=sqlc.arg(uuid))
ON CONFLICT(mapping_arn,shard_id) DO UPDATE SET parent_id=excluded.parent_id,adjacent_parent_id=excluded.adjacent_parent_id,starting_position_timestamp=excluded.starting_position_timestamp,retention_nanoseconds=excluded.retention_nanoseconds,checkpoint=excluded.checkpoint,read_complete=excluded.read_complete,complete=excluded.complete;
-- name: DeleteStreamShards :exec
DELETE FROM lambda_stream_shards WHERE mapping_arn=?;
-- name: ListStreamLanes :many
SELECT * FROM lambda_stream_lanes WHERE mapping_arn=? AND shard_id=? ORDER BY lane;
-- name: DeleteStreamLanes :exec
DELETE FROM lambda_stream_lanes WHERE mapping_arn=? AND shard_id=?;
-- name: PutStreamLane :exec
INSERT INTO lambda_stream_lanes(mapping_arn,shard_id,lane,window_start,window_end,window_state,window_final,window_early) VALUES (?,?,?,?,?,?,?,?);
-- name: ListStreamRecords :many
SELECT * FROM lambda_stream_records WHERE mapping_arn=? AND shard_id=? AND lane=? ORDER BY ordinal;
-- name: PutStreamRecord :exec
INSERT INTO lambda_stream_records(mapping_arn,shard_id,lane,ordinal,record_id,sequence_number,item_key,created_at,captured_at,payload) VALUES (?,?,?,?,?,?,?,?,?,?);
-- name: ListStreamBatches :many
SELECT * FROM lambda_stream_batches WHERE mapping_arn=? AND shard_id=? AND lane=? ORDER BY ordinal;
-- name: PutStreamBatch :exec
INSERT INTO lambda_stream_batches(mapping_arn,shard_id,lane,ordinal,record_count,attempts,due,last_event_id,last_request_id,executed_version,function_error,invoke_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);
-- name: ListStreamFailures :many
SELECT * FROM lambda_stream_failures ORDER BY created_at,id;
-- name: PutStreamFailure :exec
INSERT INTO lambda_stream_failures(id,partition,account,region,mapping_uuid,function_name,function_qualifier,role_arn,destination_arn,shard_id,record_count,created_at,parent_event_id,payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING;
-- name: DeleteStreamFailure :exec
DELETE FROM lambda_stream_failures WHERE id=?;
