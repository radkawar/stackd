-- name: GetNode :one
SELECT * FROM ssm_nodes WHERE partition = ? AND account_id = ? AND region = ? AND node_id = ?;

-- name: ListNodes :many
SELECT * FROM ssm_nodes WHERE partition = ? AND account_id = ? AND region = ? ORDER BY node_id;

-- name: PutNode :exec
INSERT INTO ssm_nodes (partition, account_id, region, node_id, agent_version, agent_name, platform_type, platform_name, platform_version, computer_name, registered_at, last_ping)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(node_id), sqlc.arg(agent_version), sqlc.arg(agent_name), sqlc.arg(platform_type), sqlc.arg(platform_name), sqlc.arg(platform_version), sqlc.arg(computer_name), sqlc.arg(registered_at), sqlc.arg(last_ping))
ON CONFLICT (partition, account_id, region, node_id) DO UPDATE SET
    agent_version = excluded.agent_version,
    agent_name = excluded.agent_name,
    platform_type = excluded.platform_type,
    platform_name = excluded.platform_name,
    platform_version = excluded.platform_version,
    computer_name = excluded.computer_name,
    registered_at = excluded.registered_at,
    last_ping = excluded.last_ping;

-- name: GetCommand :one
SELECT * FROM ssm_commands WHERE partition = ? AND account_id = ? AND region = ? AND command_id = ?;

-- name: GetCommandID :one
SELECT id FROM ssm_commands WHERE partition = ? AND account_id = ? AND region = ? AND command_id = ?;

-- name: ListCommands :many
SELECT * FROM ssm_commands WHERE partition = ? AND account_id = ? AND region = ? ORDER BY command_id;

-- name: NextDeadline :one
SELECT * FROM ssm_commands AS c
WHERE c.status IN ('Pending', 'InProgress', 'Cancelling')
  AND (c.empty_target_ready_at IS NOT NULL OR EXISTS (
      SELECT 1 FROM ssm_command_invocations AS i
      WHERE i.command_id = c.id AND i.status IN ('Pending', 'Delayed', 'InProgress', 'Cancelling')))
ORDER BY COALESCE(c.empty_target_ready_at, c.delivery_deadline), c.partition, c.account_id, c.region, c.command_id LIMIT 1;

-- name: PutCommand :one
INSERT INTO ssm_commands (partition, account_id, region, command_id, document_name, document_version, document_hash, content, comment, parameters_present, instance_ids_present, targets_present, requested_at, delivery_deadline, empty_target_ready_at, timeout_seconds, max_concurrency, max_errors, concurrency, error_budget, output_bucket, output_prefix, output_region, log_group, cloud_watch_enabled, status, status_details, parent_event_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(command_id), sqlc.arg(document_name), sqlc.arg(document_version), sqlc.arg(document_hash), sqlc.arg(content), sqlc.arg(comment), sqlc.arg(parameters_present), sqlc.arg(instance_ids_present), sqlc.arg(targets_present), sqlc.arg(requested_at), sqlc.arg(delivery_deadline), sqlc.arg(empty_target_ready_at), sqlc.arg(timeout_seconds), sqlc.arg(max_concurrency), sqlc.arg(max_errors), sqlc.arg(concurrency), sqlc.arg(error_budget), sqlc.arg(output_bucket), sqlc.arg(output_prefix), sqlc.arg(output_region), sqlc.arg(log_group), sqlc.arg(cloud_watch_enabled), sqlc.arg(status), sqlc.arg(status_details), sqlc.arg(parent_event_id))
ON CONFLICT (partition, account_id, region, command_id) DO UPDATE SET
    document_name = excluded.document_name,
    document_version = excluded.document_version,
    document_hash = excluded.document_hash,
    content = excluded.content,
    comment = excluded.comment,
    parameters_present = excluded.parameters_present,
    instance_ids_present = excluded.instance_ids_present,
    targets_present = excluded.targets_present,
    requested_at = excluded.requested_at,
    delivery_deadline = excluded.delivery_deadline,
    empty_target_ready_at = excluded.empty_target_ready_at,
    timeout_seconds = excluded.timeout_seconds,
    max_concurrency = excluded.max_concurrency,
    max_errors = excluded.max_errors,
    concurrency = excluded.concurrency,
    error_budget = excluded.error_budget,
    output_bucket = excluded.output_bucket,
    output_prefix = excluded.output_prefix,
    output_region = excluded.output_region,
    log_group = excluded.log_group,
    cloud_watch_enabled = excluded.cloud_watch_enabled,
    status = excluded.status,
    status_details = excluded.status_details,
    parent_event_id = excluded.parent_event_id
RETURNING id;

-- name: GetInvocation :one
SELECT * FROM ssm_command_invocations WHERE command_id = ? AND node_id = ?;

-- name: ListInvocations :many
SELECT * FROM ssm_command_invocations WHERE command_id = ? ORDER BY node_id;

-- name: ListNodeInvocationCommands :many
SELECT c.command_id FROM ssm_commands AS c
JOIN ssm_command_invocations AS i ON i.command_id = c.id
WHERE c.partition = ? AND c.account_id = ? AND c.region = ? AND i.node_id = ?
ORDER BY c.requested_at, c.command_id;

-- name: PutInvocation :one
INSERT INTO ssm_command_invocations (command_id, node_id, instance_name, status, status_details, trace, delivery_id, cancel_id, cancel_job_id, delivered_at, started_at, finished_at, retry_at, delivery_acknowledged, cancel_acknowledged, plugins_present, reply_ids_present)
VALUES (sqlc.arg(command_id), sqlc.arg(node_id), sqlc.arg(instance_name), sqlc.arg(status), sqlc.arg(status_details), sqlc.arg(trace), sqlc.arg(delivery_id), sqlc.arg(cancel_id), sqlc.arg(cancel_job_id), sqlc.arg(delivered_at), sqlc.arg(started_at), sqlc.arg(finished_at), sqlc.arg(retry_at), sqlc.arg(delivery_acknowledged), sqlc.arg(cancel_acknowledged), sqlc.arg(plugins_present), sqlc.arg(reply_ids_present))
ON CONFLICT (command_id, node_id) DO UPDATE SET
    instance_name = excluded.instance_name,
    status = excluded.status,
    status_details = excluded.status_details,
    trace = excluded.trace,
    delivery_id = excluded.delivery_id,
    cancel_id = excluded.cancel_id,
    cancel_job_id = excluded.cancel_job_id,
    delivered_at = excluded.delivered_at,
    started_at = excluded.started_at,
    finished_at = excluded.finished_at,
    retry_at = excluded.retry_at,
    delivery_acknowledged = excluded.delivery_acknowledged,
    cancel_acknowledged = excluded.cancel_acknowledged,
    plugins_present = excluded.plugins_present,
    reply_ids_present = excluded.reply_ids_present
RETURNING id;

-- name: ListParameters :many
SELECT * FROM ssm_command_parameters WHERE command_id = ? ORDER BY name;

-- name: PutParameters :exec
INSERT INTO ssm_command_parameters (command_id, name, values_present) VALUES (sqlc.arg(command_id), sqlc.arg(name), sqlc.arg(values_present));

-- name: DeleteParameters :exec
DELETE FROM ssm_command_parameters WHERE command_id = ?;

-- name: ListParameterValues :many
SELECT * FROM ssm_command_parameter_values WHERE command_id = ? AND name = ? ORDER BY position;

-- name: PutParameterValues :exec
INSERT INTO ssm_command_parameter_values (command_id, name, position, value) VALUES (sqlc.arg(command_id), sqlc.arg(name), sqlc.arg(position), sqlc.arg(value));

-- name: ListInstanceIDs :many
SELECT * FROM ssm_command_instance_ids WHERE command_id = ? ORDER BY position;

-- name: PutInstanceIDs :exec
INSERT INTO ssm_command_instance_ids (command_id, position, node_id) VALUES (sqlc.arg(command_id), sqlc.arg(position), sqlc.arg(node_id));

-- name: DeleteInstanceIDs :exec
DELETE FROM ssm_command_instance_ids WHERE command_id = ?;

-- name: ListTargets :many
SELECT * FROM ssm_command_targets WHERE command_id = ? ORDER BY position;

-- name: PutTargets :exec
INSERT INTO ssm_command_targets (command_id, position, target_key, values_present) VALUES (sqlc.arg(command_id), sqlc.arg(position), sqlc.arg(target_key), sqlc.arg(values_present));

-- name: DeleteTargets :exec
DELETE FROM ssm_command_targets WHERE command_id = ?;

-- name: ListTargetValues :many
SELECT * FROM ssm_command_target_values WHERE command_id = ? AND target_position = ? ORDER BY position;

-- name: PutTargetValues :exec
INSERT INTO ssm_command_target_values (command_id, target_position, position, value) VALUES (sqlc.arg(command_id), sqlc.arg(target_position), sqlc.arg(position), sqlc.arg(value));

-- name: ListPlugins :many
SELECT * FROM ssm_command_plugins WHERE invocation_id = ? ORDER BY position;

-- name: PutPlugins :exec
INSERT INTO ssm_command_plugins (invocation_id, position, name, action, status, status_details, code, output, standard_output, standard_error, started_at, finished_at, output_bucket, output_prefix) VALUES (sqlc.arg(invocation_id), sqlc.arg(position), sqlc.arg(name), sqlc.arg(action), sqlc.arg(status), sqlc.arg(status_details), sqlc.arg(code), sqlc.arg(output), sqlc.arg(standard_output), sqlc.arg(standard_error), sqlc.arg(started_at), sqlc.arg(finished_at), sqlc.arg(output_bucket), sqlc.arg(output_prefix));

-- name: DeletePlugins :exec
DELETE FROM ssm_command_plugins WHERE invocation_id = ?;

-- name: ListReplyIDs :many
SELECT * FROM ssm_command_reply_ids WHERE invocation_id = ? ORDER BY position;

-- name: PutReplyIDs :exec
INSERT INTO ssm_command_reply_ids (invocation_id, position, reply_id) VALUES (sqlc.arg(invocation_id), sqlc.arg(position), sqlc.arg(reply_id));

-- name: DeleteReplyIDs :exec
DELETE FROM ssm_command_reply_ids WHERE invocation_id = ?;

-- name: GetNotificationConfig :one
SELECT * FROM ssm_command_notification_config WHERE command_id = ?;

-- name: PutNotificationConfig :exec
INSERT INTO ssm_command_notification_config (command_id, service_role_arn, service_role_id, notification_arn, notification_type)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (command_id) DO UPDATE SET service_role_arn = excluded.service_role_arn, service_role_id = excluded.service_role_id, notification_arn = excluded.notification_arn, notification_type = excluded.notification_type;

-- name: ListNotificationEvents :many
SELECT event FROM ssm_command_notification_events WHERE command_id = ? ORDER BY position;

-- name: DeleteNotificationEvents :exec
DELETE FROM ssm_command_notification_events WHERE command_id = ?;

-- name: PutNotificationEvent :exec
INSERT INTO ssm_command_notification_events (command_id, position, event) VALUES (?, ?, ?);

-- name: GetNotification :one
SELECT n.*, c.partition, c.account_id, c.region, c.command_id AS command_key
FROM ssm_command_notifications n JOIN ssm_commands c ON c.id = n.command_id WHERE n.id = ?;

-- name: NextNotification :one
SELECT n.*, c.partition, c.account_id, c.region, c.command_id AS command_key
FROM ssm_command_notifications n JOIN ssm_commands c ON c.id = n.command_id
WHERE n.message_id = '' ORDER BY n.due, n.id LIMIT 1;

-- name: PutNotification :exec
INSERT INTO ssm_command_notifications (id, command_id, node_id, status, status_details, event_time, due, revision, message_id, delivered_at, last_error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET due = excluded.due, revision = excluded.revision, message_id = excluded.message_id, delivered_at = excluded.delivered_at, last_error = excluded.last_error;

-- name: GetAlarm :one
SELECT * FROM ssm_command_alarms WHERE command_id = ?;

-- name: PutAlarm :exec
INSERT INTO ssm_command_alarms (command_id, alarm_name, ignore_poll_failure, role_id, due, revision, checked, triggered_state, last_error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (command_id) DO UPDATE SET alarm_name = excluded.alarm_name, ignore_poll_failure = excluded.ignore_poll_failure, role_id = excluded.role_id, due = excluded.due, revision = excluded.revision, checked = excluded.checked, triggered_state = excluded.triggered_state, last_error = excluded.last_error;

-- name: DeleteAlarm :exec
DELETE FROM ssm_command_alarms WHERE command_id = ?;

-- name: NextAlarmPoll :one
SELECT c.* FROM ssm_commands c JOIN ssm_command_alarms a ON a.command_id = c.id
WHERE a.due IS NOT NULL AND c.status IN ('Pending', 'InProgress')
ORDER BY a.due, c.partition, c.account_id, c.region, c.command_id LIMIT 1;

-- name: AlarmRegions :many
SELECT DISTINCT c.region FROM ssm_commands c JOIN ssm_command_alarms a ON a.command_id = c.id
WHERE c.partition = ? AND c.account_id = ? AND c.status IN ('Pending', 'InProgress', 'Cancelling')
ORDER BY c.region;
