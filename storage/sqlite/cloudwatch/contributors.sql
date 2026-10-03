-- name: ListAlarmContributors :many
SELECT * FROM cloudwatch_alarm_contributors
WHERE alarm_id = sqlc.arg(alarm_id) AND contributor_id > sqlc.arg(after_id)
ORDER BY contributor_id LIMIT sqlc.arg(page_limit);

-- name: PutAlarmContributor :exec
INSERT INTO cloudwatch_alarm_contributors (alarm_id, contributor_id, reason, transitioned)
VALUES (?, ?, ?, ?)
ON CONFLICT(alarm_id, contributor_id) DO UPDATE SET reason=excluded.reason, transitioned=excluded.transitioned;

-- name: DeleteAlarmContributor :exec
DELETE FROM cloudwatch_alarm_contributors WHERE alarm_id = ? AND contributor_id = ?;

-- name: ListAlarmContributorAttributes :many
SELECT key, value FROM cloudwatch_alarm_contributor_attributes
WHERE alarm_id = ? AND contributor_id = ? ORDER BY key;

-- name: PutAlarmContributorAttribute :exec
INSERT INTO cloudwatch_alarm_contributor_attributes (alarm_id, contributor_id, key, value) VALUES (?, ?, ?, ?);

-- name: DeleteAlarmContributorAttributes :exec
DELETE FROM cloudwatch_alarm_contributor_attributes WHERE alarm_id = ? AND contributor_id = ?;

-- name: ListAlarmHistoryContributorAttributes :many
SELECT key, value FROM cloudwatch_alarm_history_contributor_attributes WHERE history_id = ? ORDER BY key;

-- name: PutAlarmHistoryContributorAttribute :exec
INSERT INTO cloudwatch_alarm_history_contributor_attributes (history_id, key, value) VALUES (?, ?, ?);

-- name: ListAlarmActionContributorAttributes :many
SELECT key, value FROM cloudwatch_alarm_action_contributor_attributes WHERE action_id = ? ORDER BY key;

-- name: PutAlarmActionContributorAttribute :exec
INSERT INTO cloudwatch_alarm_action_contributor_attributes (action_id, key, value) VALUES (?, ?, ?);

-- name: DeleteAlarmActionContributorAttributes :exec
DELETE FROM cloudwatch_alarm_action_contributor_attributes WHERE action_id = ?;
