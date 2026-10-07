-- name: GetMachine :one
SELECT * FROM stepfunctions_machines WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListMachines :many
SELECT * FROM stepfunctions_machines WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: CountMachines :one
SELECT COUNT(*) FROM stepfunctions_machines WHERE partition = ? AND account_id = ? AND region = ?;
-- name: PutMachine :exec
INSERT INTO stepfunctions_machines (partition, account_id, region, name, id, revision_id, type, status, created, version, delete_at, next_version, first_version_description, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET id = excluded.id, revision_id = excluded.revision_id, type = excluded.type, status = excluded.status, created = excluded.created, version = excluded.version, delete_at = excluded.delete_at, next_version = excluded.next_version, first_version_description = excluded.first_version_description;
-- name: DeleteMachine :execrows
DELETE FROM stepfunctions_machines WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListMachineTags :many
SELECT key, value FROM stepfunctions_machine_tags WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? ORDER BY key;
-- name: DeleteMachineTags :exec
DELETE FROM stepfunctions_machine_tags WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ?;
-- name: PutMachineTag :exec
INSERT INTO stepfunctions_machine_tags (partition, account_id, region, machine_name, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetRevision :one
SELECT * FROM stepfunctions_revisions WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;
-- name: PutRevision :exec
INSERT INTO stepfunctions_revisions (partition, account_id, region, id, machine_name, machine_id, created, definition, role_arn, log_group_arn, initial, log_level, include_execution_data, tracing_enabled, encryption_type, kms_key_arn, data_key_reuse_seconds, encrypted_data_key, encrypted_content, definition_identity, needs_nested_sync, needs_ecs_sync)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO NOTHING;
-- name: DeleteUnreferencedRevision :exec
DELETE FROM stepfunctions_revisions
WHERE stepfunctions_revisions.partition = ? AND stepfunctions_revisions.account_id = ? AND stepfunctions_revisions.region = ? AND stepfunctions_revisions.id = ?
AND NOT EXISTS (SELECT 1 FROM stepfunctions_machines m WHERE m.partition = stepfunctions_revisions.partition AND m.account_id = stepfunctions_revisions.account_id AND m.region = stepfunctions_revisions.region AND m.revision_id = stepfunctions_revisions.id)
AND NOT EXISTS (SELECT 1 FROM stepfunctions_versions v WHERE v.partition = stepfunctions_revisions.partition AND v.account_id = stepfunctions_revisions.account_id AND v.region = stepfunctions_revisions.region AND v.revision_id = stepfunctions_revisions.id)
AND NOT EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = stepfunctions_revisions.partition AND e.account_id = stepfunctions_revisions.account_id AND e.region = stepfunctions_revisions.region AND e.revision_id = stepfunctions_revisions.id);

-- name: GetVersion :one
SELECT * FROM stepfunctions_versions WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND number = ?;
-- name: ListVersions :many
SELECT * FROM stepfunctions_versions WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? ORDER BY number DESC;
-- name: PutVersion :exec
INSERT INTO stepfunctions_versions (partition, account_id, region, machine_name, machine_id, number, revision_id, created, description, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, machine_name, machine_id, number) DO UPDATE SET revision_id = excluded.revision_id, created = excluded.created, description = excluded.description, cfn_owner = excluded.cfn_owner;
-- name: DeleteVersion :execrows
DELETE FROM stepfunctions_versions WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND number = ?;

-- name: GetAlias :one
SELECT * FROM stepfunctions_aliases WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND name = ?;
-- name: ListAliases :many
SELECT * FROM stepfunctions_aliases WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? ORDER BY name;
-- name: PutAlias :exec
INSERT INTO stepfunctions_aliases (partition, account_id, region, machine_name, machine_id, name, description, created, updated, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, machine_name, machine_id, name) DO UPDATE SET description = excluded.description, created = excluded.created, updated = excluded.updated, cfn_owner = excluded.cfn_owner;
-- name: DeleteAlias :execrows
DELETE FROM stepfunctions_aliases WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND name = ?;
-- name: ListAliasRoutes :many
SELECT version, weight FROM stepfunctions_alias_routes WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND alias_name = ? ORDER BY position;
-- name: DeleteAliasRoutes :exec
DELETE FROM stepfunctions_alias_routes WHERE partition = ? AND account_id = ? AND region = ? AND machine_name = ? AND machine_id = ? AND alias_name = ?;
-- name: PutAliasRoute :exec
INSERT INTO stepfunctions_alias_routes (partition, account_id, region, machine_name, machine_id, alias_name, position, version, weight) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetActivity :one
SELECT * FROM stepfunctions_activities WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListActivities :many
SELECT * FROM stepfunctions_activities WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: CountActivities :one
SELECT COUNT(*) FROM stepfunctions_activities WHERE partition = ? AND account_id = ? AND region = ?;
-- name: PutActivity :exec
INSERT INTO stepfunctions_activities (partition, account_id, region, name, id, created, encryption_type, kms_key_arn, data_key_reuse_seconds, cfn_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET id = excluded.id, created = excluded.created, encryption_type = excluded.encryption_type, kms_key_arn = excluded.kms_key_arn, data_key_reuse_seconds = excluded.data_key_reuse_seconds;
-- name: DeleteActivity :execrows
DELETE FROM stepfunctions_activities WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListActivityTags :many
SELECT key, value FROM stepfunctions_activity_tags WHERE partition = ? AND account_id = ? AND region = ? AND activity_name = ? ORDER BY key;
-- name: DeleteActivityTags :exec
DELETE FROM stepfunctions_activity_tags WHERE partition = ? AND account_id = ? AND region = ? AND activity_name = ?;
-- name: PutActivityTag :exec
INSERT INTO stepfunctions_activity_tags (partition, account_id, region, activity_name, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetExecution :one
SELECT * FROM stepfunctions_executions WHERE partition = ? AND account_id = ? AND region = ? AND arn = ?;
-- name: ListExecutions :many
SELECT * FROM stepfunctions_executions
WHERE partition = ? AND account_id = ? AND region = ?
AND (CAST(sqlc.arg(machine_id) AS TEXT) = '' OR machine_id = sqlc.arg(machine_id))
AND (CAST(sqlc.arg(version_arn) AS TEXT) = '' OR version_arn = sqlc.arg(version_arn))
AND (CAST(sqlc.arg(alias_arn) AS TEXT) = '' OR alias_arn = sqlc.arg(alias_arn))
AND (CAST(sqlc.arg(map_run_arn) AS TEXT) = '' OR map_run_arn = sqlc.arg(map_run_arn))
AND (CAST(sqlc.arg(status) AS TEXT) = '' OR status = sqlc.arg(status))
ORDER BY started DESC, arn;
-- name: CountOpenExecutions :one
SELECT COUNT(*) FROM stepfunctions_executions WHERE partition = ? AND account_id = ? AND region = ? AND type = 'STANDARD' AND status = 'RUNNING';
-- name: PutExecution :exec
INSERT INTO stepfunctions_executions (partition, account_id, region, arn, machine_name, machine_id, revision_id, name, type, version_arn, alias_arn, map_run_arn, map_item_count, parent_event_id, trace_header, status, input, output, error, cause, started, stopped, deadline, expires, version, next_frame_id, next_history_id, delivered_history_id, peak_memory_bytes, redrive_count, redriven, map_generation, trace_segment_id, encrypted_data_key, encrypted_content)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET machine_name = excluded.machine_name, machine_id = excluded.machine_id, revision_id = excluded.revision_id, name = excluded.name, type = excluded.type, version_arn = excluded.version_arn, alias_arn = excluded.alias_arn, map_run_arn = excluded.map_run_arn, map_item_count = excluded.map_item_count, parent_event_id = excluded.parent_event_id, trace_header = excluded.trace_header, status = excluded.status, input = excluded.input, output = excluded.output, error = excluded.error, cause = excluded.cause, started = excluded.started, stopped = excluded.stopped, deadline = excluded.deadline, expires = excluded.expires, version = excluded.version, next_frame_id = excluded.next_frame_id, next_history_id = excluded.next_history_id, delivered_history_id = excluded.delivered_history_id, peak_memory_bytes = excluded.peak_memory_bytes, redrive_count = excluded.redrive_count, redriven = excluded.redriven, map_generation = excluded.map_generation, trace_segment_id = excluded.trace_segment_id, encrypted_data_key = excluded.encrypted_data_key, encrypted_content = excluded.encrypted_content;
-- name: DeleteExecution :execrows
DELETE FROM stepfunctions_executions WHERE partition = ? AND account_id = ? AND region = ? AND arn = ?;
-- name: ListOwnedExecutions :many
WITH RECURSIVE owned(partition, account_id, region, arn) AS (
 SELECT e.partition, e.account_id, e.region, e.arn FROM stepfunctions_executions e
 WHERE e.partition = ? AND e.account_id = ? AND e.region = ? AND e.arn = ?
 UNION
 SELECT child.partition, child.account_id, child.region, child.arn
 FROM owned parent
 JOIN stepfunctions_map_runs m ON m.partition = parent.partition AND m.account_id = parent.account_id AND m.region = parent.region AND m.execution_arn = parent.arn
 JOIN stepfunctions_executions child ON child.partition = m.partition AND child.account_id = m.account_id AND child.region = m.region AND child.map_run_arn = m.arn
)
SELECT e.arn, e.revision_id FROM stepfunctions_executions e
JOIN owned o ON o.partition = e.partition AND o.account_id = e.account_id AND o.region = e.region AND o.arn = e.arn
ORDER BY e.arn;

-- name: ListRedriveRequests :many
SELECT token, count, date FROM stepfunctions_redrive_requests WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? ORDER BY count;
-- name: DeleteRedriveRequests :exec
DELETE FROM stepfunctions_redrive_requests WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ?;
-- name: PutRedriveRequest :exec
INSERT INTO stepfunctions_redrive_requests (partition, account_id, region, execution_arn, token, count, date) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetFrame :one
SELECT * FROM stepfunctions_frames WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? AND id = ?;
-- name: ListFrames :many
SELECT * FROM stepfunctions_frames WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? ORDER BY id;
-- name: PutFrame :exec
INSERT INTO stepfunctions_frames (partition, account_id, region, execution_arn, id, parent_id, parent_state_id, parent_attempt, branch_index, scope_path, state_name, phase, input, variables, arguments, output, error, cause, entered, entered_history_id, previous_history_id, task_id, retry_count, next_item, item_count, max_concurrency, map_run_arn, due, version, child_generation, started_history_id, encrypted_data_key, encrypted_content)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, execution_arn, id) DO UPDATE SET parent_id = excluded.parent_id, parent_state_id = excluded.parent_state_id, parent_attempt = excluded.parent_attempt, branch_index = excluded.branch_index, scope_path = excluded.scope_path, state_name = excluded.state_name, phase = excluded.phase, input = excluded.input, variables = excluded.variables, arguments = excluded.arguments, output = excluded.output, error = excluded.error, cause = excluded.cause, entered = excluded.entered, entered_history_id = excluded.entered_history_id, previous_history_id = excluded.previous_history_id, task_id = excluded.task_id, retry_count = excluded.retry_count, next_item = excluded.next_item, item_count = excluded.item_count, max_concurrency = excluded.max_concurrency, map_run_arn = excluded.map_run_arn, due = excluded.due, version = excluded.version, child_generation = excluded.child_generation, started_history_id = excluded.started_history_id, encrypted_data_key = excluded.encrypted_data_key, encrypted_content = excluded.encrypted_content;
-- name: ListFrameRetries :many
SELECT retrier, count FROM stepfunctions_frame_retries WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? AND frame_id = ? ORDER BY retrier;
-- name: DeleteFrameRetries :exec
DELETE FROM stepfunctions_frame_retries WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? AND frame_id = ?;
-- name: PutFrameRetry :exec
INSERT INTO stepfunctions_frame_retries (partition, account_id, region, execution_arn, frame_id, retrier, count) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetTask :one
SELECT * FROM stepfunctions_tasks WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;
-- name: GetTaskByToken :one
SELECT * FROM stepfunctions_tasks WHERE partition = ? AND account_id = ? AND region = ? AND token = ? AND token <> '';
-- name: ListActivityTasks :many
SELECT t.* FROM stepfunctions_tasks t
WHERE t.partition = ? AND t.account_id = ? AND t.region = ? AND t.activity = ? AND t.status = 'SCHEDULED'
AND EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = t.partition AND e.account_id = t.account_id AND e.region = t.region AND e.arn = t.execution_arn AND e.status = 'RUNNING')
ORDER BY t.scheduled, t.id;
-- name: ListRecoverableTasks :many
SELECT * FROM stepfunctions_tasks WHERE (status = 'RUNNING' AND kind <> 'activity') OR (status = 'SUBMITTED' AND kind = 'sync') ORDER BY id, partition, account_id, region;
-- name: PutTask :exec
INSERT INTO stepfunctions_tasks (partition, account_id, region, id, execution_arn, frame_id, attempt, token, kind, resource, parameters, role_arn, activity, status, scheduled, started, timeout_seconds, heartbeat_seconds, deadline, heartbeat_deadline, worker_name, output, error, cause, history_id, version, encrypted_data_key, encrypted_content, input_data_key, input_content)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET execution_arn = excluded.execution_arn, frame_id = excluded.frame_id, attempt = excluded.attempt, token = excluded.token, kind = excluded.kind, resource = excluded.resource, parameters = excluded.parameters, role_arn = excluded.role_arn, activity = excluded.activity, status = excluded.status, scheduled = excluded.scheduled, started = excluded.started, timeout_seconds = excluded.timeout_seconds, heartbeat_seconds = excluded.heartbeat_seconds, deadline = excluded.deadline, heartbeat_deadline = excluded.heartbeat_deadline, worker_name = excluded.worker_name, output = excluded.output, error = excluded.error, cause = excluded.cause, history_id = excluded.history_id, version = excluded.version, encrypted_data_key = excluded.encrypted_data_key, encrypted_content = excluded.encrypted_content, input_data_key = excluded.input_data_key, input_content = excluded.input_content;

-- name: ListHistory :many
SELECT event, frame_id, state_id, redrive_count, error, cause, encrypted_data_key, encrypted_content FROM stepfunctions_history WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? ORDER BY event_id;
-- name: GetHistoryEvent :one
SELECT event, frame_id, state_id, redrive_count, error, cause, encrypted_data_key, encrypted_content FROM stepfunctions_history WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? AND event_id = ?;
-- name: AppendHistory :exec
INSERT INTO stepfunctions_history (partition, account_id, region, execution_arn, event_id, at, event, frame_id, state_id, redrive_count, error, cause, encrypted_data_key, encrypted_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetMapRun :one
SELECT * FROM stepfunctions_map_runs WHERE partition = ? AND account_id = ? AND region = ? AND arn = ?;
-- name: ListMapRuns :many
SELECT * FROM stepfunctions_map_runs WHERE partition = ? AND account_id = ? AND region = ? AND execution_arn = ? ORDER BY started DESC, arn;
-- name: PutMapRun :exec
INSERT INTO stepfunctions_map_runs (partition, account_id, region, arn, execution_arn, frame_id, label, status, started, stopped, max_concurrency, tolerated_failure_count, tolerated_failure_percentage, total_items, results_written_items, results_written_executions, redrive_count, redriven)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET execution_arn = excluded.execution_arn, frame_id = excluded.frame_id, label = excluded.label, status = excluded.status, started = excluded.started, stopped = excluded.stopped, max_concurrency = excluded.max_concurrency, tolerated_failure_count = excluded.tolerated_failure_count, tolerated_failure_percentage = excluded.tolerated_failure_percentage, total_items = excluded.total_items, results_written_items = excluded.results_written_items, results_written_executions = excluded.results_written_executions, redrive_count = excluded.redrive_count, redriven = excluded.redriven;

-- name: ListMapResultFiles :many
SELECT generation, status, file_index, key, size, first_execution, last_execution FROM stepfunctions_map_result_files WHERE partition = ? AND account_id = ? AND region = ? AND map_run_arn = ? ORDER BY generation, status, file_index;
-- name: PutMapResultFile :exec
INSERT INTO stepfunctions_map_result_files (partition, account_id, region, map_run_arn, generation, status, file_index, key, size, first_execution, last_execution)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, map_run_arn, generation, status, file_index) DO UPDATE SET key = excluded.key, size = excluded.size, first_execution = excluded.first_execution, last_execution = excluded.last_execution;

-- Work is projected from the owning resource, never copied to a durable queue.
-- Each query returns its first candidate in WorkRecord.Key tie order. Go compares
-- the candidates with CompareWork to obtain the global earliest owner.
-- name: NextMachineDelete :one
SELECT m.partition, m.account_id, m.region, m.name, m.version, m.delete_at FROM stepfunctions_machines m
WHERE m.delete_at IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = m.partition AND e.account_id = m.account_id AND e.region = m.region AND e.machine_id = m.id AND e.status = 'RUNNING')
ORDER BY m.delete_at, m.partition || '|' || m.account_id || '|' || m.region || '|' || m.name || '||00000000000000000000|' LIMIT 1;
-- name: NextExecutionTimeout :one
SELECT partition, account_id, region, arn, version, deadline FROM stepfunctions_executions WHERE status = 'RUNNING' ORDER BY deadline, partition || '|' || account_id || '|' || region || '||' || arn || '|00000000000000000000|' LIMIT 1;
-- name: NextExecutionExpiry :one
SELECT partition, account_id, region, arn, version, expires FROM stepfunctions_executions WHERE status <> 'RUNNING' AND expires IS NOT NULL ORDER BY expires, partition || '|' || account_id || '|' || region || '||' || arn || '|00000000000000000000|' LIMIT 1;
-- name: NextFrame :one
SELECT f.partition, f.account_id, f.region, f.execution_arn, f.id, f.version, f.due FROM stepfunctions_frames f WHERE f.due IS NOT NULL
AND EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = f.partition AND e.account_id = f.account_id AND e.region = f.region AND e.arn = f.execution_arn AND e.status = 'RUNNING')
ORDER BY f.due, f.partition || '|' || f.account_id || '|' || f.region || '||' || f.execution_arn || '|' || printf('%020d', f.id) || '|' LIMIT 1;
-- name: NextTaskDispatch :one
SELECT t.partition, t.account_id, t.region, t.execution_arn, t.frame_id, t.id, t.version, t.scheduled FROM stepfunctions_tasks t WHERE t.status = 'SCHEDULED' AND t.kind <> 'activity'
AND EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = t.partition AND e.account_id = t.account_id AND e.region = t.region AND e.arn = t.execution_arn AND e.status = 'RUNNING')
ORDER BY t.scheduled, t.partition || '|' || t.account_id || '|' || t.region || '||' || t.execution_arn || '|' || printf('%020d', t.frame_id) || '|' || t.id LIMIT 1;
-- name: NextTaskTimeout :one
SELECT t.partition, t.account_id, t.region, t.execution_arn, t.frame_id, t.id, t.version, t.deadline FROM stepfunctions_tasks t WHERE t.status IN ('RUNNING', 'SUBMITTED') AND t.deadline IS NOT NULL
AND EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = t.partition AND e.account_id = t.account_id AND e.region = t.region AND e.arn = t.execution_arn AND e.status = 'RUNNING')
ORDER BY t.deadline, t.partition || '|' || t.account_id || '|' || t.region || '||' || t.execution_arn || '|' || printf('%020d', t.frame_id) || '|' || t.id LIMIT 1;
-- name: NextHeartbeatTimeout :one
SELECT t.partition, t.account_id, t.region, t.execution_arn, t.frame_id, t.id, t.version, t.heartbeat_deadline FROM stepfunctions_tasks t WHERE t.status IN ('RUNNING', 'SUBMITTED') AND t.heartbeat_deadline IS NOT NULL
AND EXISTS (SELECT 1 FROM stepfunctions_executions e WHERE e.partition = t.partition AND e.account_id = t.account_id AND e.region = t.region AND e.arn = t.execution_arn AND e.status = 'RUNNING')
ORDER BY t.heartbeat_deadline, t.partition || '|' || t.account_id || '|' || t.region || '||' || t.execution_arn || '|' || printf('%020d', t.frame_id) || '|' || t.id LIMIT 1;
-- name: NextHistoryDelivery :one
SELECT e.partition, e.account_id, e.region, e.arn, e.version, h.at
FROM stepfunctions_executions e
JOIN stepfunctions_revisions r ON r.partition = e.partition AND r.account_id = e.account_id AND r.region = e.region AND r.id = e.revision_id
JOIN stepfunctions_history h ON h.partition = e.partition AND h.account_id = e.account_id AND h.region = e.region AND h.execution_arn = e.arn AND h.event_id = e.delivered_history_id + 1
WHERE e.delivered_history_id < e.next_history_id AND (r.log_level NOT IN ('', 'OFF') OR e.trace_segment_id <> '') AND h.at IS NOT NULL
ORDER BY h.at, e.partition || '|' || e.account_id || '|' || e.region || '||' || e.arn || '|00000000000000000000|' LIMIT 1;
