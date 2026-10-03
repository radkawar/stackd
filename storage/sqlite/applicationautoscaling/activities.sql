-- name: PutActivity :one
INSERT INTO aas_activities (
 partition, account_id, region, activity_id, namespace, resource_id, dimension,
 cause, description, details, start_time, end_time, status_code, status_message,
 policy_name, capacity_from, capacity_to, origin_event_id
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(activity_id),
 sqlc.arg(namespace), sqlc.arg(resource_id), sqlc.arg(dimension),
 sqlc.arg(cause), sqlc.arg(description), sqlc.arg(details), sqlc.arg(start_time), sqlc.arg(end_time),
 sqlc.arg(status_code), sqlc.arg(status_message), sqlc.arg(policy_name), sqlc.arg(capacity_from), sqlc.arg(capacity_to), sqlc.arg(origin_event_id)
)
ON CONFLICT(partition, account_id, region, activity_id) DO UPDATE SET
 namespace = excluded.namespace, resource_id = excluded.resource_id, dimension = excluded.dimension,
 cause = excluded.cause, description = excluded.description, details = excluded.details,
 start_time = excluded.start_time, end_time = excluded.end_time,
 status_code = excluded.status_code, status_message = excluded.status_message,
 policy_name = excluded.policy_name, capacity_from = excluded.capacity_from, capacity_to = excluded.capacity_to, origin_event_id = excluded.origin_event_id
RETURNING activity_pk;

-- name: ListActivities :many
SELECT * FROM aas_activities
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND namespace = sqlc.arg(namespace)
 AND (CAST(sqlc.arg(filter_resource_id) AS TEXT) = '' OR resource_id = sqlc.arg(filter_resource_id))
 AND (CAST(sqlc.arg(filter_dimension) AS TEXT) = '' OR dimension = sqlc.arg(filter_dimension))
 AND start_time >= sqlc.arg(since)
 AND (CAST(sqlc.arg(include_not_scaled) AS INTEGER) != 0 OR NOT EXISTS (SELECT 1 FROM aas_activity_reasons WHERE aas_activity_reasons.activity_pk = aas_activities.activity_pk))
 AND (CAST(sqlc.arg(from_sequence) AS INTEGER) = 0 OR start_time < sqlc.arg(from_time) OR (start_time = sqlc.arg(from_time) AND activity_pk <= sqlc.arg(from_sequence)))
ORDER BY start_time DESC, activity_pk DESC LIMIT sqlc.arg(row_limit);

-- name: ListPendingActivities :many
SELECT * FROM aas_activities
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND namespace = sqlc.arg(namespace) AND resource_id = sqlc.arg(resource_id) AND dimension = sqlc.arg(dimension)
 AND status_code IN ('Pending', 'InProgress')
ORDER BY start_time DESC, activity_pk DESC;

-- name: NextPendingActivity :many
SELECT * FROM aas_activities WHERE status_code = 'Pending' ORDER BY start_time, activity_pk LIMIT 1;

-- name: DeleteActivityReasons :exec
DELETE FROM aas_activity_reasons WHERE activity_pk = ?;

-- name: PutActivityReason :exec
INSERT INTO aas_activity_reasons(activity_pk, position, code, current_capacity, min_capacity, max_capacity)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListActivityReasons :many
SELECT * FROM aas_activity_reasons WHERE activity_pk = ? ORDER BY position;

-- name: DeleteActivitiesBefore :exec
DELETE FROM aas_activities
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND start_time < sqlc.arg(before_time);
