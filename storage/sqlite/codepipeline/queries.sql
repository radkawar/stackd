-- name: PutPipelines :exec
INSERT INTO codepipeline_pipelines (partition, account_id, region, name, incarnation, version, created_at, updated_at, polling_disabled_at, ownership, last_update) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(created_at), sqlc.arg(updated_at), sqlc.arg(polling_disabled_at), sqlc.arg(ownership), sqlc.arg(last_update)) ON CONFLICT (incarnation) DO UPDATE SET partition = excluded.partition, account_id = excluded.account_id, region = excluded.region, name = excluded.name, version = excluded.version, created_at = excluded.created_at, updated_at = excluded.updated_at, polling_disabled_at = excluded.polling_disabled_at, ownership = excluded.ownership, last_update = excluded.last_update;

-- name: PutTags :exec
INSERT INTO codepipeline_tags (incarnation, tag_key, tag_value) VALUES (sqlc.arg(incarnation), sqlc.arg(tag_key), sqlc.arg(tag_value)) ON CONFLICT (incarnation,tag_key) DO UPDATE SET tag_value = excluded.tag_value;

-- name: PutTransitions :exec
INSERT INTO codepipeline_transitions (incarnation, stage_name, transition_type, disabled, reason, changed_by, changed_at) VALUES (sqlc.arg(incarnation), sqlc.arg(stage_name), sqlc.arg(transition_type), sqlc.arg(disabled), sqlc.arg(reason), sqlc.arg(changed_by), sqlc.arg(changed_at)) ON CONFLICT (incarnation,stage_name,transition_type) DO UPDATE SET disabled = excluded.disabled, reason = excluded.reason, changed_by = excluded.changed_by, changed_at = excluded.changed_at;

-- name: PutDefinitions :exec
INSERT INTO codepipeline_definitions (incarnation, version, partition, account_id, region, name, role_arn, execution_mode, pipeline_type, artifact_bucket, encryption_key, encryption_type, variables_present) VALUES (sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(role_arn), sqlc.arg(execution_mode), sqlc.arg(pipeline_type), sqlc.arg(artifact_bucket), sqlc.arg(encryption_key), sqlc.arg(encryption_type), sqlc.arg(variables_present)) ON CONFLICT (incarnation,version) DO UPDATE SET partition = excluded.partition, account_id = excluded.account_id, region = excluded.region, name = excluded.name, role_arn = excluded.role_arn, execution_mode = excluded.execution_mode, pipeline_type = excluded.pipeline_type, artifact_bucket = excluded.artifact_bucket, encryption_key = excluded.encryption_key, encryption_type = excluded.encryption_type, variables_present = excluded.variables_present;

-- name: PutStages :exec
INSERT INTO codepipeline_stages (incarnation, version, stage_index, name) VALUES (sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(stage_index), sqlc.arg(name)) ON CONFLICT (incarnation,version,stage_index) DO UPDATE SET name = excluded.name;

-- name: PutActions :exec
INSERT INTO codepipeline_actions (incarnation, version, stage_index, action_index, name, category, owner, provider, action_version, role_arn, region, run_order, timeout_minutes, namespace) VALUES (sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(stage_index), sqlc.arg(action_index), sqlc.arg(name), sqlc.arg(category), sqlc.arg(owner), sqlc.arg(provider), sqlc.arg(action_version), sqlc.arg(role_arn), sqlc.arg(region), sqlc.arg(run_order), sqlc.arg(timeout_minutes), sqlc.arg(namespace)) ON CONFLICT (incarnation,version,stage_index,action_index) DO UPDATE SET name = excluded.name, category = excluded.category, owner = excluded.owner, provider = excluded.provider, action_version = excluded.action_version, role_arn = excluded.role_arn, region = excluded.region, run_order = excluded.run_order, timeout_minutes = excluded.timeout_minutes, namespace = excluded.namespace;

-- name: PutConfiguration :exec
INSERT INTO codepipeline_configuration (incarnation, version, stage_index, action_index, config_key, config_value) VALUES (sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(stage_index), sqlc.arg(action_index), sqlc.arg(config_key), sqlc.arg(config_value)) ON CONFLICT (incarnation,version,stage_index,action_index,config_key) DO UPDATE SET config_value = excluded.config_value;

-- name: PutDeclarations :exec
INSERT INTO codepipeline_declarations (incarnation, version, stage_index, action_index, direction, position, name) VALUES (sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(stage_index), sqlc.arg(action_index), sqlc.arg(direction), sqlc.arg(position), sqlc.arg(name)) ON CONFLICT (incarnation,version,stage_index,action_index,direction,position) DO UPDATE SET name = excluded.name;

-- name: PutExecutions :exec
INSERT INTO codepipeline_executions (
 execution_id, partition, account_id, region, pipeline_name, incarnation, version,
 client_token, mode, status, summary, trigger_type, trigger_detail,
 stop_reason, stage_index, stage_entered, updated_definition, started_at, updated_at,
 due, generation, sequence, parent_event_id, attempt, stage_status,
 stage_started_at, last_retry_at, stage_last_retry_at, rollback_target_id, rollback_stage_index
) VALUES (
 sqlc.arg(execution_id), sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region),
 sqlc.arg(pipeline_name), sqlc.arg(incarnation), sqlc.arg(version), sqlc.arg(client_token),
 sqlc.arg(mode), sqlc.arg(status), sqlc.arg(summary),
 sqlc.arg(trigger_type), sqlc.arg(trigger_detail), sqlc.arg(stop_reason),
 sqlc.arg(stage_index), sqlc.arg(stage_entered), sqlc.arg(updated_definition),
 sqlc.arg(started_at), sqlc.arg(updated_at), sqlc.arg(due), sqlc.arg(generation),
 sqlc.arg(sequence), sqlc.arg(parent_event_id), sqlc.arg(attempt), sqlc.arg(stage_status),
 sqlc.arg(stage_started_at), sqlc.arg(last_retry_at), sqlc.arg(stage_last_retry_at),
 sqlc.arg(rollback_target_id), sqlc.arg(rollback_stage_index)
) ON CONFLICT (execution_id) DO UPDATE SET
 partition = excluded.partition, account_id = excluded.account_id, region = excluded.region,
 pipeline_name = excluded.pipeline_name, incarnation = excluded.incarnation, version = excluded.version,
 client_token = excluded.client_token, mode = excluded.mode,
 status = excluded.status, summary = excluded.summary, trigger_type = excluded.trigger_type,
 trigger_detail = excluded.trigger_detail, stop_reason = excluded.stop_reason, stage_index = excluded.stage_index,
 stage_entered = excluded.stage_entered, updated_definition = excluded.updated_definition,
 started_at = excluded.started_at, updated_at = excluded.updated_at, due = excluded.due,
 generation = excluded.generation, sequence = excluded.sequence, parent_event_id = excluded.parent_event_id,
 attempt = excluded.attempt, stage_status = excluded.stage_status,
 stage_started_at = excluded.stage_started_at,
 last_retry_at = excluded.last_retry_at, stage_last_retry_at = excluded.stage_last_retry_at,
 rollback_target_id = excluded.rollback_target_id, rollback_stage_index = excluded.rollback_stage_index;

-- name: PutOverrides :exec
INSERT INTO codepipeline_overrides (execution_id, position, action_name, revision_type, revision_value) VALUES (sqlc.arg(execution_id), sqlc.arg(position), sqlc.arg(action_name), sqlc.arg(revision_type), sqlc.arg(revision_value)) ON CONFLICT (execution_id,position) DO UPDATE SET action_name = excluded.action_name, revision_type = excluded.revision_type, revision_value = excluded.revision_value;

-- name: PutRevisions :exec
INSERT INTO codepipeline_revisions (execution_id, position, action_name, artifact_name, revision_id, change_id, summary, url, created_at) VALUES (sqlc.arg(execution_id), sqlc.arg(position), sqlc.arg(action_name), sqlc.arg(artifact_name), sqlc.arg(revision_id), sqlc.arg(change_id), sqlc.arg(summary), sqlc.arg(url), sqlc.arg(created_at)) ON CONFLICT (execution_id,position) DO UPDATE SET action_name = excluded.action_name, artifact_name = excluded.artifact_name, revision_id = excluded.revision_id, change_id = excluded.change_id, summary = excluded.summary, url = excluded.url, created_at = excluded.created_at;

-- name: PutActionExecutions :exec
INSERT INTO codepipeline_action_executions (
 action_id, execution_id, position, stage_name, action_name, status, stage_index,
 action_index, attempt, started_at, updated_at, external_id, external_url,
 summary, error_code, error_message, approval_token, updated_by, approval_notification_id
) VALUES (
 sqlc.arg(action_id), sqlc.arg(execution_id), sqlc.arg(position), sqlc.arg(stage_name),
 sqlc.arg(action_name), sqlc.arg(status), sqlc.arg(stage_index), sqlc.arg(action_index),
 sqlc.arg(attempt), sqlc.arg(started_at), sqlc.arg(updated_at), sqlc.arg(external_id),
 sqlc.arg(external_url), sqlc.arg(summary), sqlc.arg(error_code), sqlc.arg(error_message),
 sqlc.arg(approval_token), sqlc.arg(updated_by), sqlc.arg(approval_notification_id)
) ON CONFLICT (action_id) DO UPDATE SET
 execution_id = excluded.execution_id, position = excluded.position,
 stage_name = excluded.stage_name, action_name = excluded.action_name, status = excluded.status,
 stage_index = excluded.stage_index, action_index = excluded.action_index, attempt = excluded.attempt,
 started_at = excluded.started_at, updated_at = excluded.updated_at, external_id = excluded.external_id,
 external_url = excluded.external_url, summary = excluded.summary, error_code = excluded.error_code,
 error_message = excluded.error_message, approval_token = excluded.approval_token, updated_by = excluded.updated_by,
 approval_notification_id = excluded.approval_notification_id;

-- name: PutArtifacts :exec
INSERT INTO codepipeline_artifacts (action_id, direction, position, name, bucket, object_key, version_id, etag, revision_id, producer_id) VALUES (sqlc.arg(action_id), sqlc.arg(direction), sqlc.arg(position), sqlc.arg(name), sqlc.arg(bucket), sqlc.arg(object_key), sqlc.arg(version_id), sqlc.arg(etag), sqlc.arg(revision_id), sqlc.arg(producer_id)) ON CONFLICT (action_id,direction,position) DO UPDATE SET name = excluded.name, bucket = excluded.bucket, object_key = excluded.object_key, version_id = excluded.version_id, etag = excluded.etag, revision_id = excluded.revision_id, producer_id = excluded.producer_id;

-- name: ListPipelines :many
SELECT * FROM codepipeline_pipelines WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: DeletePipeline :exec
DELETE FROM codepipeline_pipelines WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetDefinition :one
SELECT * FROM codepipeline_definitions WHERE partition = ? AND account_id = ? AND region = ? AND incarnation = ? AND version = ?;

-- name: ListExecutions :many
SELECT * FROM codepipeline_executions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND (incarnation = sqlc.arg(incarnation) OR sqlc.arg(incarnation) = '') ORDER BY started_at, sequence, execution_id;

-- name: PendingExecutions :many
SELECT * FROM codepipeline_executions WHERE due != 0 ORDER BY due, sequence, execution_id;

-- name: FenceDeletedExecutions :exec
UPDATE codepipeline_executions SET due = 0, generation = generation + 1 WHERE incarnation = ?;

-- name: ListTags :many
SELECT * FROM codepipeline_tags WHERE incarnation = ? ORDER BY incarnation,tag_key;

-- name: DeleteTags :exec
DELETE FROM codepipeline_tags WHERE incarnation = ?;

-- name: ListTransitions :many
SELECT * FROM codepipeline_transitions WHERE incarnation = ? ORDER BY incarnation,stage_name,transition_type;

-- name: DeleteTransitions :exec
DELETE FROM codepipeline_transitions WHERE incarnation = ?;

-- name: ListStages :many
SELECT * FROM codepipeline_stages WHERE incarnation = ? AND version = ? ORDER BY incarnation,version,stage_index;

-- name: DeleteStages :exec
DELETE FROM codepipeline_stages WHERE incarnation = ? AND version = ?;

-- name: ListActions :many
SELECT * FROM codepipeline_actions WHERE incarnation = ? AND version = ? ORDER BY incarnation,version,stage_index,action_index;

-- name: DeleteActions :exec
DELETE FROM codepipeline_actions WHERE incarnation = ? AND version = ?;

-- name: ListConfiguration :many
SELECT * FROM codepipeline_configuration WHERE incarnation = ? AND version = ? ORDER BY incarnation,version,stage_index,action_index,config_key;

-- name: DeleteConfiguration :exec
DELETE FROM codepipeline_configuration WHERE incarnation = ? AND version = ?;

-- name: ListDeclarations :many
SELECT * FROM codepipeline_declarations WHERE incarnation = ? AND version = ? ORDER BY incarnation,version,stage_index,action_index,direction,position;

-- name: DeleteDeclarations :exec
DELETE FROM codepipeline_declarations WHERE incarnation = ? AND version = ?;

-- name: ListOverrides :many
SELECT * FROM codepipeline_overrides WHERE execution_id = ? ORDER BY execution_id,position;

-- name: DeleteOverrides :exec
DELETE FROM codepipeline_overrides WHERE execution_id = ?;

-- name: ListRevisions :many
SELECT * FROM codepipeline_revisions WHERE execution_id = ? ORDER BY execution_id,position;

-- name: DeleteRevisions :exec
DELETE FROM codepipeline_revisions WHERE execution_id = ?;

-- name: ListActionExecutions :many
SELECT * FROM codepipeline_action_executions WHERE execution_id = ? ORDER BY position;

-- name: DeleteActionExecutions :exec
DELETE FROM codepipeline_action_executions WHERE execution_id = ?;

-- name: ListArtifacts :many
SELECT * FROM codepipeline_artifacts WHERE action_id = ? ORDER BY action_id,direction,position;

-- name: DeleteArtifacts :exec
DELETE FROM codepipeline_artifacts WHERE action_id = ?;

-- name: PutActionValues :exec
INSERT INTO codepipeline_action_values (action_id,value_kind,value_key,value_text) VALUES (?,?,?,?) ON CONFLICT (action_id,value_kind,value_key) DO UPDATE SET value_text = excluded.value_text;

-- name: ListActionValues :many
SELECT * FROM codepipeline_action_values WHERE action_id = ? ORDER BY value_kind,value_key;

-- name: DeleteActionValues :exec
DELETE FROM codepipeline_action_values WHERE action_id = ?;

-- name: PutVariableDeclarations :exec
INSERT INTO codepipeline_variable_declarations (incarnation,version,position,name,default_value,description) VALUES (?,?,?,?,?,?);

-- name: ListVariableDeclarations :many
SELECT * FROM codepipeline_variable_declarations WHERE incarnation = ? AND version = ? ORDER BY position;

-- name: DeleteVariableDeclarations :exec
DELETE FROM codepipeline_variable_declarations WHERE incarnation = ? AND version = ?;

-- name: PutExecutionVariables :exec
INSERT INTO codepipeline_execution_variables (execution_id,position,name,resolved_value) VALUES (?,?,?,?);

-- name: ListExecutionVariables :many
SELECT * FROM codepipeline_execution_variables WHERE execution_id = ? ORDER BY position;

-- name: DeleteExecutionVariables :exec
DELETE FROM codepipeline_execution_variables WHERE execution_id = ?;

-- name: ListSourcePolls :many
SELECT * FROM codepipeline_source_polls
WHERE partition = ? AND account_id = ? AND region = ? AND incarnation = ?
ORDER BY stage_name, action_name;

-- name: PendingSourcePolls :many
SELECT * FROM codepipeline_source_polls WHERE due != 0
ORDER BY due, partition, account_id, region, incarnation, stage_name, action_name;

-- name: PutSourcePoll :exec
INSERT INTO codepipeline_source_polls (
 partition, account_id, region, incarnation, pipeline_name, pipeline_version,
 stage_name, action_name, bucket, object_key, revision_id, poll_id,
 parent_event_id, generation, due, error_code, error_message, last_attempt
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(incarnation),
 sqlc.arg(pipeline_name), sqlc.arg(pipeline_version), sqlc.arg(stage_name),
 sqlc.arg(action_name), sqlc.arg(bucket), sqlc.arg(object_key), sqlc.arg(revision_id),
 sqlc.arg(poll_id), sqlc.arg(parent_event_id), sqlc.arg(generation), sqlc.arg(due),
 sqlc.arg(error_code), sqlc.arg(error_message), sqlc.arg(last_attempt)
) ON CONFLICT (partition, account_id, region, incarnation, stage_name, action_name)
DO UPDATE SET pipeline_name = excluded.pipeline_name, pipeline_version = excluded.pipeline_version,
 bucket = excluded.bucket, object_key = excluded.object_key, revision_id = excluded.revision_id,
 poll_id = excluded.poll_id, parent_event_id = excluded.parent_event_id,
 generation = excluded.generation, due = excluded.due, error_code = excluded.error_code,
 error_message = excluded.error_message, last_attempt = excluded.last_attempt;

-- name: DeleteSourcePolls :exec
DELETE FROM codepipeline_source_polls
WHERE partition = ? AND account_id = ? AND region = ? AND incarnation = ?;

-- name: GetInvocationJob :one
SELECT * FROM codepipeline_invocation_jobs
WHERE partition = ? AND account_id = ? AND region = ? AND job_id = ?;

-- name: ListInvocationJobs :many
SELECT * FROM codepipeline_invocation_jobs
WHERE partition = ? AND account_id = ? AND region = ? AND action_id = ?
ORDER BY sequence;

-- name: PutInvocationJob :exec
INSERT INTO codepipeline_invocation_jobs (
 partition, account_id, region, job_id, pipeline_name, incarnation, execution_id,
 action_id, stage_name, action_name, status, continuation_token, result_continuation_token, sequence, generation,
 created_at, expires_at, action_expires_at, execution_details_present, execution_external_id,
 execution_percent, execution_summary, failure_details_present, failure_external_id,
 failure_message, failure_type, current_revision_present, revision_change_id,
 revision_created, revision_id, revision_summary, output_variables_present
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(job_id),
 sqlc.arg(pipeline_name), sqlc.arg(incarnation), sqlc.arg(execution_id),
 sqlc.arg(action_id), sqlc.arg(stage_name), sqlc.arg(action_name), sqlc.arg(status),
 sqlc.arg(continuation_token), sqlc.arg(result_continuation_token), sqlc.arg(sequence), sqlc.arg(generation),
 sqlc.arg(created_at), sqlc.arg(expires_at), sqlc.arg(action_expires_at), sqlc.arg(execution_details_present),
 sqlc.narg(execution_external_id), sqlc.narg(execution_percent), sqlc.narg(execution_summary),
 sqlc.arg(failure_details_present), sqlc.narg(failure_external_id),
 sqlc.narg(failure_message), sqlc.narg(failure_type), sqlc.arg(current_revision_present),
 sqlc.narg(revision_change_id), sqlc.narg(revision_created), sqlc.narg(revision_id),
 sqlc.narg(revision_summary), sqlc.arg(output_variables_present)
) ON CONFLICT (partition, account_id, region, job_id) DO UPDATE SET
 pipeline_name = excluded.pipeline_name, incarnation = excluded.incarnation,
 execution_id = excluded.execution_id, action_id = excluded.action_id,
 stage_name = excluded.stage_name, action_name = excluded.action_name,
 status = excluded.status, continuation_token = excluded.continuation_token,
 result_continuation_token = excluded.result_continuation_token,
 sequence = excluded.sequence, generation = excluded.generation,
 created_at = excluded.created_at, expires_at = excluded.expires_at,
 action_expires_at = excluded.action_expires_at,
 execution_details_present = excluded.execution_details_present,
 execution_external_id = excluded.execution_external_id,
 execution_percent = excluded.execution_percent, execution_summary = excluded.execution_summary,
 failure_details_present = excluded.failure_details_present,
 failure_external_id = excluded.failure_external_id, failure_message = excluded.failure_message,
 failure_type = excluded.failure_type, current_revision_present = excluded.current_revision_present,
 revision_change_id = excluded.revision_change_id, revision_created = excluded.revision_created,
 revision_id = excluded.revision_id, revision_summary = excluded.revision_summary,
 output_variables_present = excluded.output_variables_present;

-- name: ListInvocationJobVariables :many
SELECT name, value FROM codepipeline_invocation_job_variables
WHERE partition = ? AND account_id = ? AND region = ? AND job_id = ?
ORDER BY name;

-- name: DeleteInvocationJobVariables :exec
DELETE FROM codepipeline_invocation_job_variables
WHERE partition = ? AND account_id = ? AND region = ? AND job_id = ?;

-- name: PutInvocationJobVariable :exec
INSERT INTO codepipeline_invocation_job_variables
 (partition, account_id, region, job_id, name, value)
VALUES (?, ?, ?, ?, ?, ?);
