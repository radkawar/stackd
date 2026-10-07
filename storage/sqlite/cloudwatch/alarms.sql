-- name: GetAlarm :one
SELECT * FROM cloudwatch_alarms WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetAlarmByID :one
SELECT * FROM cloudwatch_alarms WHERE id = ?;

-- name: ListAlarms :many
SELECT cloudwatch_alarms.* FROM cloudwatch_alarms
WHERE cloudwatch_alarms.partition = sqlc.arg(partition) AND cloudwatch_alarms.account_id = sqlc.arg(account_id) AND cloudwatch_alarms.region = sqlc.arg(region)
 AND cloudwatch_alarms.name >= sqlc.arg(from_name)
 AND (CAST(sqlc.arg(has_after) AS INTEGER) = 0 OR cloudwatch_alarms.name > sqlc.arg(after_name))
 AND (sqlc.arg(prefix) = '' OR instr(cloudwatch_alarms.name, sqlc.arg(prefix)) = 1)
 AND (sqlc.arg(state) = '' OR cloudwatch_alarms.state_value = sqlc.arg(state))
 AND (sqlc.arg(action_prefix) = '' OR EXISTS (SELECT 1 FROM cloudwatch_alarm_targets t WHERE t.alarm_id = cloudwatch_alarms.id AND instr(t.arn, sqlc.arg(action_prefix)) = 1))
 AND (sqlc.arg(parent_of) = '' OR EXISTS (SELECT 1 FROM cloudwatch_alarm_children c WHERE c.alarm_id = cloudwatch_alarms.id AND c.name = sqlc.arg(parent_of)))
 AND (sqlc.arg(suppressed_by) = '' OR EXISTS (SELECT 1 FROM cloudwatch_alarm_composite_configs c WHERE c.alarm_id = cloudwatch_alarms.id AND (c.suppressor = sqlc.arg(suppressed_by) OR c.suppressor = 'arn:' || cloudwatch_alarms.partition || ':cloudwatch:' || cloudwatch_alarms.region || ':' || cloudwatch_alarms.account_id || ':alarm:' || sqlc.arg(suppressed_by))))
ORDER BY cloudwatch_alarms.name LIMIT sqlc.arg(page_limit);

-- name: NextAlarmEvaluation :one
SELECT id, version, next_evaluation, suppression_until FROM cloudwatch_alarms
WHERE next_evaluation IS NOT NULL OR suppression_until IS NOT NULL
ORDER BY CASE WHEN next_evaluation IS NULL THEN suppression_until
              WHEN suppression_until IS NULL THEN next_evaluation
              WHEN next_evaluation <= suppression_until THEN next_evaluation
              ELSE suppression_until END, id LIMIT 1;

-- name: PutAlarm :exec
INSERT INTO cloudwatch_alarms (id, partition, account_id, region, name, alarm_type, version, created, updated, description, actions_enabled, state_value, state_reason, state_reason_data, state_updated, state_transitioned, state_event_id, state_request_id, next_evaluation, suppression_phase, suppression_reason, suppression_until, evaluation_event_id, evaluation_request_id, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, alarm_type=excluded.alarm_type, version=excluded.version, created=excluded.created, updated=excluded.updated, description=excluded.description, actions_enabled=excluded.actions_enabled, state_value=excluded.state_value, state_reason=excluded.state_reason, state_reason_data=excluded.state_reason_data, state_updated=excluded.state_updated, state_transitioned=excluded.state_transitioned, state_event_id=excluded.state_event_id, state_request_id=excluded.state_request_id, next_evaluation=excluded.next_evaluation, suppression_phase=excluded.suppression_phase, suppression_reason=excluded.suppression_reason, suppression_until=excluded.suppression_until, evaluation_event_id=excluded.evaluation_event_id, evaluation_request_id=excluded.evaluation_request_id, cfn_owner=excluded.cfn_owner;

-- name: UpdateAlarmEvaluation :execrows
UPDATE cloudwatch_alarms SET version = ?, state_value = ?, state_reason = ?, state_reason_data = ?,
 state_updated = ?, state_transitioned = ?, next_evaluation = ?, suppression_phase = ?,
 suppression_reason = ?, suppression_until = ?, state_event_id = ?, state_request_id = ?,
 evaluation_event_id = ?, evaluation_request_id = ? WHERE id = ?;

-- name: DeleteAlarm :exec
DELETE FROM cloudwatch_alarms WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetAlarmMetricConfig :one
SELECT * FROM cloudwatch_alarm_metric_configs WHERE alarm_id = ?;

-- name: PutAlarmMetricConfig :exec
INSERT INTO cloudwatch_alarm_metric_configs (alarm_id, query_id, comparison, threshold, evaluation_periods, datapoints_to_alarm, treat_missing_data, low_sample_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteAlarmMetricConfig :exec
DELETE FROM cloudwatch_alarm_metric_configs WHERE alarm_id = ?;

-- name: ListAlarmQueries :many
SELECT * FROM cloudwatch_alarm_queries WHERE alarm_id = ? ORDER BY position;

-- name: PutAlarmQuery :exec
INSERT INTO cloudwatch_alarm_queries (alarm_id, position, query_id, expression, account_id, label, period, return_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteAlarmQueries :exec
DELETE FROM cloudwatch_alarm_queries WHERE alarm_id = ?;

-- name: ListAlarmMetricStats :many
SELECT * FROM cloudwatch_alarm_metric_stats WHERE alarm_id = ? ORDER BY position;

-- name: PutAlarmMetricStat :exec
INSERT INTO cloudwatch_alarm_metric_stats (alarm_id, position, partition, account_id, region, namespace, name, dimensions, period, statistic, unit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteAlarmMetricStats :exec
DELETE FROM cloudwatch_alarm_metric_stats WHERE alarm_id = ?;

-- name: ListAlarmDimensions :many
SELECT * FROM cloudwatch_alarm_dimensions WHERE alarm_id = ? ORDER BY metric_position, position;

-- name: PutAlarmDimension :exec
INSERT INTO cloudwatch_alarm_dimensions (alarm_id, metric_position, position, name, value) VALUES (?, ?, ?, ?, ?);

-- name: GetAlarmCompositeConfig :one
SELECT * FROM cloudwatch_alarm_composite_configs WHERE alarm_id = ?;

-- name: PutAlarmCompositeConfig :exec
INSERT INTO cloudwatch_alarm_composite_configs (alarm_id, rule, suppressor, wait_period, extension_period) VALUES (?, ?, ?, ?, ?);

-- name: DeleteAlarmCompositeConfig :exec
DELETE FROM cloudwatch_alarm_composite_configs WHERE alarm_id = ?;

-- name: ListAlarmChildren :many
SELECT name FROM cloudwatch_alarm_children WHERE alarm_id = ? ORDER BY position;

-- name: PutAlarmChild :exec
INSERT INTO cloudwatch_alarm_children (alarm_id, position, name) VALUES (?, ?, ?);

-- name: DeleteAlarmChildren :exec
DELETE FROM cloudwatch_alarm_children WHERE alarm_id = ?;

-- name: ListAlarmTargets :many
SELECT * FROM cloudwatch_alarm_targets WHERE alarm_id = ? ORDER BY state, position;

-- name: PutAlarmTarget :exec
INSERT INTO cloudwatch_alarm_targets (alarm_id, state, position, arn) VALUES (?, ?, ?, ?);

-- name: DeleteAlarmTargets :exec
DELETE FROM cloudwatch_alarm_targets WHERE alarm_id = ?;

-- name: ListAlarmTags :many
SELECT key, value FROM cloudwatch_alarm_tags WHERE alarm_id = ? ORDER BY key;

-- name: PutAlarmTag :exec
INSERT INTO cloudwatch_alarm_tags (alarm_id, key, value) VALUES (?, ?, ?);

-- name: DeleteAlarmTags :exec
DELETE FROM cloudwatch_alarm_tags WHERE alarm_id = ?;

-- name: ListAlarmHistoryAscending :many
SELECT * FROM cloudwatch_alarm_history
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND (sqlc.arg(name) = '' OR name = sqlc.arg(name))
 AND (sqlc.arg(type) = '' OR type = sqlc.arg(type))
 AND (CAST(sqlc.arg(contributor_id) AS TEXT) = '' OR contributor_id = CAST(sqlc.arg(contributor_id) AS TEXT))
 AND (contributor_id IS NOT NULL) = CAST(sqlc.arg(contributors) AS INTEGER)
 AND (CAST(sqlc.arg(has_start) AS INTEGER) = 0 OR at >= sqlc.arg(start_time))
 AND (CAST(sqlc.arg(has_end) AS INTEGER) = 0 OR at <= sqlc.arg(end_time))
 AND (CAST(sqlc.arg(has_after) AS INTEGER) = 0 OR at > sqlc.arg(after_at) OR (at = sqlc.arg(after_at) AND id > sqlc.arg(after_id)))
ORDER BY at, id LIMIT sqlc.arg(page_limit);

-- name: ListAlarmHistoryDescending :many
SELECT * FROM cloudwatch_alarm_history
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND (sqlc.arg(name) = '' OR name = sqlc.arg(name))
 AND (sqlc.arg(type) = '' OR type = sqlc.arg(type))
 AND (CAST(sqlc.arg(contributor_id) AS TEXT) = '' OR contributor_id = CAST(sqlc.arg(contributor_id) AS TEXT))
 AND (contributor_id IS NOT NULL) = CAST(sqlc.arg(contributors) AS INTEGER)
 AND (CAST(sqlc.arg(has_start) AS INTEGER) = 0 OR at >= sqlc.arg(start_time))
 AND (CAST(sqlc.arg(has_end) AS INTEGER) = 0 OR at <= sqlc.arg(end_time))
 AND (CAST(sqlc.arg(has_after) AS INTEGER) = 0 OR at < sqlc.arg(after_at) OR (at = sqlc.arg(after_at) AND id < sqlc.arg(after_id)))
ORDER BY at DESC, id DESC LIMIT sqlc.arg(page_limit);

-- name: AppendAlarmHistory :exec
INSERT INTO cloudwatch_alarm_history (id, partition, account_id, region, name, alarm_type, type, summary, at, data, contributor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAlarmAction :one
SELECT * FROM cloudwatch_alarm_actions WHERE id = ?;

-- name: NextAlarmAction :one
SELECT id, version, due FROM cloudwatch_alarm_actions ORDER BY due, id LIMIT 1;

-- name: PutAlarmAction :exec
INSERT INTO cloudwatch_alarm_actions (id, event_id, request_id, partition, account_id, region, name, alarm_type, target_arn, state, payload, subject, accepted, due, version, attempts, contributor_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET event_id=excluded.event_id, request_id=excluded.request_id, partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, alarm_type=excluded.alarm_type, target_arn=excluded.target_arn, state=excluded.state, payload=excluded.payload, subject=excluded.subject, accepted=excluded.accepted, due=excluded.due, version=excluded.version, attempts=excluded.attempts, contributor_id=excluded.contributor_id;

-- name: DeleteAlarmAction :exec
DELETE FROM cloudwatch_alarm_actions WHERE id = ?;

-- name: ExpireAlarmHistory :exec
DELETE FROM cloudwatch_alarm_history
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id)
 AND region = sqlc.arg(region) AND at < sqlc.arg(cutoff);
