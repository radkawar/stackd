-- name: GetReplay :one
SELECT * FROM eventbridge_replays WHERE partition=? AND account=? AND region=? AND name=?;
-- name: ListReplays :many
SELECT * FROM eventbridge_replays WHERE partition=? AND account=? AND region=? ORDER BY name;
-- name: NextReplay :one
SELECT * FROM eventbridge_replays WHERE state IN ('STARTING','RUNNING','CANCELLING') ORDER BY due_seconds,due_nanos,partition,account,region,name LIMIT 1;
-- name: NextReplayExpiration :one
SELECT * FROM eventbridge_replays WHERE finished_seconds IS NOT NULL AND state IN ('COMPLETED','CANCELLED','FAILED') ORDER BY finished_seconds,finished_nanos,partition,account,region,name LIMIT 1;
-- name: PutReplay :exec
INSERT INTO eventbridge_replays(partition,account,region,name,archive_partition,archive_account,archive_region,archive_name,archive_id,destination_partition,destination_account,destination_region,destination_bus_name,description,start_time,end_time,started,finished_seconds,finished_nanos,due_seconds,due_nanos,cursor_seconds,cursor_nanos,cursor_id,state,state_reason,version,request_id,actor_arn)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,name) DO UPDATE SET archive_partition=excluded.archive_partition,archive_account=excluded.archive_account,archive_region=excluded.archive_region,archive_name=excluded.archive_name,archive_id=excluded.archive_id,destination_partition=excluded.destination_partition,destination_account=excluded.destination_account,destination_region=excluded.destination_region,destination_bus_name=excluded.destination_bus_name,description=excluded.description,start_time=excluded.start_time,end_time=excluded.end_time,started=excluded.started,finished_seconds=excluded.finished_seconds,finished_nanos=excluded.finished_nanos,due_seconds=excluded.due_seconds,due_nanos=excluded.due_nanos,cursor_seconds=excluded.cursor_seconds,cursor_nanos=excluded.cursor_nanos,cursor_id=excluded.cursor_id,state=excluded.state,state_reason=excluded.state_reason,version=excluded.version,request_id=excluded.request_id,actor_arn=excluded.actor_arn;
-- name: DeleteReplay :exec
DELETE FROM eventbridge_replays WHERE partition=? AND account=? AND region=? AND name=?;
-- name: GetReplayFilters :many
SELECT arn FROM eventbridge_replay_filters WHERE partition=? AND account=? AND region=? AND replay_name=? ORDER BY position;
-- name: DeleteReplayFilters :exec
DELETE FROM eventbridge_replay_filters WHERE partition=? AND account=? AND region=? AND replay_name=?;
-- name: PutReplayFilter :exec
INSERT INTO eventbridge_replay_filters(partition,account,region,replay_name,position,arn) VALUES(?,?,?,?,?,?);
