-- name: GetDashboard :one
SELECT * FROM cloudwatch_dashboards
WHERE partition = ? AND account_id = ? AND name = ?;

-- name: ListDashboards :many
SELECT partition, account_id, name, updated, size FROM cloudwatch_dashboards
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id)
 AND name > sqlc.arg(after_name)
 AND substr(name, 1, length(CAST(sqlc.arg(prefix) AS TEXT))) = CAST(sqlc.arg(prefix) AS TEXT)
ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: PutDashboard :exec
INSERT INTO cloudwatch_dashboards (partition, account_id, name, body, updated, size, tagging_initialized, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, name) DO UPDATE SET
 body = excluded.body, updated = excluded.updated, size = excluded.size,
 tagging_initialized = excluded.tagging_initialized, cfn_owner = excluded.cfn_owner;

-- name: DeleteDashboard :exec
DELETE FROM cloudwatch_dashboards WHERE partition = ? AND account_id = ? AND name = ?;

-- name: ListDashboardTags :many
SELECT key, value FROM cloudwatch_dashboard_tags
WHERE partition = ? AND account_id = ? AND dashboard_name = ? ORDER BY key;

-- name: PutDashboardTag :exec
INSERT INTO cloudwatch_dashboard_tags (partition, account_id, dashboard_name, key, value)
VALUES (?, ?, ?, ?, ?);

-- name: DeleteDashboardTags :exec
DELETE FROM cloudwatch_dashboard_tags WHERE partition = ? AND account_id = ? AND dashboard_name = ?;
