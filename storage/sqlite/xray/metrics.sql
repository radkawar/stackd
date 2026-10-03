-- name: NextGroupMetric :one
SELECT partition, account_id, region, group_id, group_name, minute, count
FROM xray_group_metrics
ORDER BY minute, partition, account_id, region, group_id LIMIT 1;

-- name: AddGroupMetric :exec
INSERT INTO xray_group_metrics (partition, account_id, region, group_id, group_name, minute, count)
VALUES (?, ?, ?, ?, ?, ?, 1)
ON CONFLICT (partition, account_id, region, group_id, minute)
DO UPDATE SET count = xray_group_metrics.count + 1;

-- name: DeleteGroupMetric :exec
DELETE FROM xray_group_metrics
WHERE partition = ? AND account_id = ? AND region = ? AND group_id = ? AND minute = ?;
