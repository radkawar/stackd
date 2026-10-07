-- name: PutTarget :one
INSERT INTO aas_targets (
 ownership,
 partition, account_id, region, namespace, resource_id, dimension, native_id, origin_event_id, reconcile_at, creation_time, max_capacity, min_capacity, predicted_capacity, data_resource_id, role_arn, data_dimension, target_arn, data_namespace, has_suspended_state, suspended_in, suspended_out, suspended_scheduled, has_tags
) VALUES (
 sqlc.arg(ownership),
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(namespace), sqlc.arg(resource_id), sqlc.arg(dimension), sqlc.arg(native_id), sqlc.arg(origin_event_id), sqlc.arg(reconcile_at), sqlc.arg(creation_time), sqlc.arg(max_capacity), sqlc.arg(min_capacity), sqlc.arg(predicted_capacity), sqlc.arg(data_resource_id), sqlc.arg(role_arn), sqlc.arg(data_dimension), sqlc.arg(target_arn), sqlc.arg(data_namespace), sqlc.arg(has_suspended_state), sqlc.arg(suspended_in), sqlc.arg(suspended_out), sqlc.arg(suspended_scheduled), sqlc.arg(has_tags)
)
ON CONFLICT(partition, account_id, region, namespace, resource_id, dimension) DO UPDATE SET
 ownership = excluded.ownership,
 native_id = excluded.native_id,
 origin_event_id = excluded.origin_event_id,
 reconcile_at = excluded.reconcile_at,
 creation_time = excluded.creation_time,
 max_capacity = excluded.max_capacity,
 min_capacity = excluded.min_capacity,
 predicted_capacity = excluded.predicted_capacity,
 data_resource_id = excluded.data_resource_id,
 role_arn = excluded.role_arn,
 data_dimension = excluded.data_dimension,
 target_arn = excluded.target_arn,
 data_namespace = excluded.data_namespace,
 has_suspended_state = excluded.has_suspended_state,
 suspended_in = excluded.suspended_in,
 suspended_out = excluded.suspended_out,
 suspended_scheduled = excluded.suspended_scheduled,
 has_tags = excluded.has_tags
RETURNING *;

-- name: GetTarget :one
SELECT * FROM aas_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension);

-- name: DeleteTarget :exec
DELETE FROM aas_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension);

-- name: ListTargets :many
SELECT * FROM aas_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND namespace = sqlc.arg(namespace)
 AND (CAST(sqlc.arg(filter_dimension) AS TEXT) = '' OR dimension = sqlc.arg(filter_dimension))
 AND (sqlc.arg(has_names) = 0 OR resource_id IN (SELECT value FROM json_each(sqlc.arg(names))))
 AND (CAST(sqlc.arg(from_resource_id) AS TEXT) = '' OR (resource_id, dimension) >= (CAST(sqlc.arg(from_resource_id) AS TEXT), CAST(sqlc.arg(from_dimension) AS TEXT)))
ORDER BY partition, account_id, region, namespace, resource_id, dimension LIMIT sqlc.arg(row_limit);

-- name: PutPolicy :one
INSERT INTO aas_policies (
 ownership,
 partition, account_id, region, namespace, resource_id, dimension, name, managed_action_id, last_scale_at, last_scale_from, last_scale_to, creation_time, policy_arn, policy_name, policy_type, data_resource_id, data_dimension, data_namespace, has_alarms, has_step, step_adjustment_type, step_cooldown, step_aggregation_type, step_min_adjustment, has_steps, has_tracking, disable_scale_in, scale_in_cooldown, scale_out_cooldown, target_value, has_predefined, predefined_metric_type, resource_label, has_custom, custom_metric_name, custom_namespace, custom_statistic, custom_unit, has_custom_dimensions, has_metric_queries
 , pending_activity_id
) VALUES (
 sqlc.arg(ownership),
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(namespace), sqlc.arg(resource_id), sqlc.arg(dimension), sqlc.arg(name), sqlc.arg(managed_action_id), sqlc.arg(last_scale_at), sqlc.arg(last_scale_from), sqlc.arg(last_scale_to), sqlc.arg(creation_time), sqlc.arg(policy_arn), sqlc.arg(policy_name), sqlc.arg(policy_type), sqlc.arg(data_resource_id), sqlc.arg(data_dimension), sqlc.arg(data_namespace), sqlc.arg(has_alarms), sqlc.arg(has_step), sqlc.arg(step_adjustment_type), sqlc.arg(step_cooldown), sqlc.arg(step_aggregation_type), sqlc.arg(step_min_adjustment), sqlc.arg(has_steps), sqlc.arg(has_tracking), sqlc.arg(disable_scale_in), sqlc.arg(scale_in_cooldown), sqlc.arg(scale_out_cooldown), sqlc.arg(target_value), sqlc.arg(has_predefined), sqlc.arg(predefined_metric_type), sqlc.arg(resource_label), sqlc.arg(has_custom), sqlc.arg(custom_metric_name), sqlc.arg(custom_namespace), sqlc.arg(custom_statistic), sqlc.arg(custom_unit), sqlc.arg(has_custom_dimensions), sqlc.arg(has_metric_queries)
 , sqlc.arg(pending_activity_id)
)
ON CONFLICT(partition, account_id, region, namespace, resource_id, dimension, name) DO UPDATE SET
 ownership = excluded.ownership,
 managed_action_id = excluded.managed_action_id,
 last_scale_at = excluded.last_scale_at,
 last_scale_from = excluded.last_scale_from,
 last_scale_to = excluded.last_scale_to,
 pending_activity_id = excluded.pending_activity_id,
 creation_time = excluded.creation_time,
 policy_arn = excluded.policy_arn,
 policy_name = excluded.policy_name,
 policy_type = excluded.policy_type,
 data_resource_id = excluded.data_resource_id,
 data_dimension = excluded.data_dimension,
 data_namespace = excluded.data_namespace,
 has_alarms = excluded.has_alarms,
 has_step = excluded.has_step,
 step_adjustment_type = excluded.step_adjustment_type,
 step_cooldown = excluded.step_cooldown,
 step_aggregation_type = excluded.step_aggregation_type,
 step_min_adjustment = excluded.step_min_adjustment,
 has_steps = excluded.has_steps,
 has_tracking = excluded.has_tracking,
 disable_scale_in = excluded.disable_scale_in,
 scale_in_cooldown = excluded.scale_in_cooldown,
 scale_out_cooldown = excluded.scale_out_cooldown,
 target_value = excluded.target_value,
 has_predefined = excluded.has_predefined,
 predefined_metric_type = excluded.predefined_metric_type,
 resource_label = excluded.resource_label,
 has_custom = excluded.has_custom,
 custom_metric_name = excluded.custom_metric_name,
 custom_namespace = excluded.custom_namespace,
 custom_statistic = excluded.custom_statistic,
 custom_unit = excluded.custom_unit,
 has_custom_dimensions = excluded.has_custom_dimensions,
 has_metric_queries = excluded.has_metric_queries
RETURNING *;

-- name: GetPolicy :one
SELECT * FROM aas_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension) AND name = sqlc.arg(name);

-- name: DeletePolicy :exec
DELETE FROM aas_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension) AND name = sqlc.arg(name);

-- name: ListPolicies :many
WITH selected_names AS (
 SELECT CAST(value AS TEXT) AS selected_name, MIN(CAST(key AS INTEGER)) AS position
 FROM json_each(sqlc.arg(names)) GROUP BY selected_name
)
SELECT * FROM aas_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND namespace = sqlc.arg(namespace)
 AND (CAST(sqlc.arg(filter_dimension) AS TEXT) = '' OR dimension = sqlc.arg(filter_dimension))
 AND (CAST(sqlc.arg(filter_resource_id) AS TEXT) = '' OR resource_id = sqlc.arg(filter_resource_id))
 AND (sqlc.arg(has_names) = 0 OR name IN (SELECT selected_name FROM selected_names))
 AND (CAST(sqlc.arg(from_resource_id) AS TEXT) = '' OR
  (sqlc.arg(has_names) = 0 AND (resource_id, dimension, name) >= (CAST(sqlc.arg(from_resource_id) AS TEXT), CAST(sqlc.arg(from_dimension) AS TEXT), CAST(sqlc.arg(from_name) AS TEXT))) OR
  (sqlc.arg(has_names) != 0 AND (
   (SELECT position FROM selected_names WHERE selected_name = aas_policies.name) > (SELECT position FROM selected_names WHERE selected_name = CAST(sqlc.arg(from_name) AS TEXT)) OR
   (name = CAST(sqlc.arg(from_name) AS TEXT) AND (resource_id, dimension) >= (CAST(sqlc.arg(from_resource_id) AS TEXT), CAST(sqlc.arg(from_dimension) AS TEXT)))
  ))
 )
ORDER BY (SELECT position FROM selected_names WHERE selected_name = aas_policies.name),
 partition, account_id, region, namespace, resource_id, dimension, name LIMIT sqlc.arg(row_limit);

-- name: PutSchedule :exec
INSERT INTO aas_schedules (
 partition, account_id, region, namespace, resource_id, dimension, name, origin_event_id, next_due, creation_time, start_time, end_time, timezone, data_resource_id, data_dimension, data_namespace, schedule, action_arn, action_name, has_action, max_capacity, min_capacity
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(namespace), sqlc.arg(resource_id), sqlc.arg(dimension), sqlc.arg(name), sqlc.arg(origin_event_id), sqlc.arg(next_due), sqlc.arg(creation_time), sqlc.arg(start_time), sqlc.arg(end_time), sqlc.arg(timezone), sqlc.arg(data_resource_id), sqlc.arg(data_dimension), sqlc.arg(data_namespace), sqlc.arg(schedule), sqlc.arg(action_arn), sqlc.arg(action_name), sqlc.arg(has_action), sqlc.arg(max_capacity), sqlc.arg(min_capacity)
)
ON CONFLICT(partition, account_id, region, namespace, resource_id, dimension, name) DO UPDATE SET
 origin_event_id = excluded.origin_event_id,
 next_due = excluded.next_due,
 creation_time = excluded.creation_time,
 start_time = excluded.start_time,
 end_time = excluded.end_time,
 timezone = excluded.timezone,
 data_resource_id = excluded.data_resource_id,
 data_dimension = excluded.data_dimension,
 data_namespace = excluded.data_namespace,
 schedule = excluded.schedule,
 action_arn = excluded.action_arn,
 action_name = excluded.action_name,
 has_action = excluded.has_action,
 max_capacity = excluded.max_capacity,
 min_capacity = excluded.min_capacity;

-- name: GetSchedule :one
SELECT * FROM aas_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension) AND name = sqlc.arg(name);

-- name: DeleteSchedule :exec
DELETE FROM aas_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension) AND name = sqlc.arg(name);

-- name: ListSchedules :many
SELECT * FROM aas_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND namespace = sqlc.arg(namespace)
 AND (CAST(sqlc.arg(filter_dimension) AS TEXT) = '' OR dimension = sqlc.arg(filter_dimension))
 AND (CAST(sqlc.arg(filter_resource_id) AS TEXT) = '' OR resource_id = sqlc.arg(filter_resource_id))
 AND (sqlc.arg(has_names) = 0 OR name IN (SELECT value FROM json_each(sqlc.arg(names))))
 AND (CAST(sqlc.arg(from_resource_id) AS TEXT) = '' OR (resource_id, dimension, name) >= (CAST(sqlc.arg(from_resource_id) AS TEXT), CAST(sqlc.arg(from_dimension) AS TEXT), CAST(sqlc.arg(from_name) AS TEXT)))
ORDER BY partition, account_id, region, namespace, resource_id, dimension, name LIMIT sqlc.arg(row_limit);

-- name: GetTargetByARN :one
SELECT * FROM aas_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND target_arn = sqlc.arg(target_arn);

-- name: ListTargetKeys :many
SELECT partition, account_id, region, namespace, resource_id, dimension FROM aas_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id)
ORDER BY partition, account_id, region, namespace, resource_id, dimension;

-- name: NextTargetReconcile :one
SELECT partition, account_id, region, namespace, resource_id, dimension, reconcile_at FROM aas_targets WHERE reconcile_at IS NOT NULL
ORDER BY reconcile_at, partition, account_id, region, namespace, resource_id, dimension LIMIT 1;

-- name: NextSchedule :one
SELECT partition, account_id, region, namespace, resource_id, dimension, name, next_due FROM aas_schedules WHERE next_due IS NOT NULL
ORDER BY next_due, partition, account_id, region, namespace, resource_id, dimension, name LIMIT 1;

-- name: DeleteTargetPolicies :exec
DELETE FROM aas_policies WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension);

-- name: DeleteTargetSchedules :exec
DELETE FROM aas_schedules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension);

-- name: ListTargetTags :many
SELECT * FROM aas_target_tags WHERE target_pk = ? ORDER BY key;

-- name: DeleteTargetTags :exec
DELETE FROM aas_target_tags WHERE target_pk = ?;

-- name: InsertTargetTag :exec
INSERT INTO aas_target_tags (target_pk, key, value) VALUES (sqlc.arg(target_pk), sqlc.arg(key), sqlc.arg(value));

-- name: ListPolicyAlarms :many
SELECT * FROM aas_policy_alarms WHERE policy_pk = ? ORDER BY position;

-- name: DeletePolicyAlarms :exec
DELETE FROM aas_policy_alarms WHERE policy_pk = ?;

-- name: InsertPolicyAlarm :exec
INSERT INTO aas_policy_alarms (policy_pk, position, alarm_arn, alarm_name) VALUES (sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(alarm_arn), sqlc.arg(alarm_name));

-- name: ListPolicySteps :many
SELECT * FROM aas_policy_steps WHERE policy_pk = ? ORDER BY position;

-- name: DeletePolicySteps :exec
DELETE FROM aas_policy_steps WHERE policy_pk = ?;

-- name: InsertPolicyStep :exec
INSERT INTO aas_policy_steps (policy_pk, position, lower_bound, upper_bound, adjustment) VALUES (sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(lower_bound), sqlc.arg(upper_bound), sqlc.arg(adjustment));

-- name: ListPolicyMetricQueries :many
SELECT * FROM aas_policy_metric_queries WHERE policy_pk = ? ORDER BY position;

-- name: DeletePolicyMetricQueries :exec
DELETE FROM aas_policy_metric_queries WHERE policy_pk = ?;

-- name: InsertPolicyMetricQuery :exec
INSERT INTO aas_policy_metric_queries (policy_pk, position, expression, query_id, label, return_data, has_stat, stat, unit, has_metric, metric_name, namespace, has_dimensions) VALUES (sqlc.arg(policy_pk), sqlc.arg(position), sqlc.arg(expression), sqlc.arg(query_id), sqlc.arg(label), sqlc.arg(return_data), sqlc.arg(has_stat), sqlc.arg(stat), sqlc.arg(unit), sqlc.arg(has_metric), sqlc.arg(metric_name), sqlc.arg(namespace), sqlc.arg(has_dimensions));

-- name: ListPolicyDimensions :many
SELECT * FROM aas_policy_dimensions WHERE policy_pk = ? ORDER BY metric_position, position;

-- name: DeletePolicyDimensions :exec
DELETE FROM aas_policy_dimensions WHERE policy_pk = ?;

-- name: InsertPolicyDimension :exec
INSERT INTO aas_policy_dimensions (policy_pk, metric_position, position, name, value) VALUES (sqlc.arg(policy_pk), sqlc.arg(metric_position), sqlc.arg(position), sqlc.arg(name), sqlc.arg(value));
