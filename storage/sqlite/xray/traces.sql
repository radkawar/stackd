-- name: GetTrace :one
SELECT * FROM xray_traces WHERE partition = ? AND account_id = ? AND region = ? AND trace_id = ?;

-- name: PutTrace :exec
INSERT INTO xray_traces (partition, account_id, region, trace_id, start_time, end_time, updated, revision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, trace_id) DO UPDATE SET
 start_time = excluded.start_time, end_time = excluded.end_time, updated = excluded.updated, revision = excluded.revision;

-- name: ListSelectedTraces :many
SELECT sqlc.embed(t), CAST(COALESCE(g.version, 0) AS INTEGER) AS group_version, g.admitted AS group_admitted,
 CAST(COALESCE(g.admitted_revision, 0) AS INTEGER) AS group_admitted_revision
FROM xray_traces t
LEFT JOIN xray_group_traces g
 ON g.partition = t.partition AND g.account_id = t.account_id AND g.region = t.region
 AND g.trace_id = t.trace_id AND g.group_id = sqlc.arg(group_id) AND CAST(sqlc.arg(group_id) AS TEXT) <> ''
WHERE t.partition = sqlc.arg(partition) AND t.account_id = sqlc.arg(account_id) AND t.region = sqlc.arg(region)
 AND (CAST(sqlc.arg(group_id) AS TEXT) = '' OR g.trace_id IS NOT NULL)
 AND (
  (CAST(sqlc.arg(kind) AS INTEGER) = 0 AND t.start_time >= sqlc.arg(start_seconds) AND t.start_time <= sqlc.arg(end_seconds))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 1 AND t.updated >= sqlc.arg(receipt_start) AND t.updated <= sqlc.arg(receipt_end))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 2 AND t.end_time >= sqlc.arg(start_seconds) AND t.start_time <= sqlc.arg(end_seconds))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 3 AND EXISTS (
   SELECT 1 FROM xray_segments c
   WHERE c.partition = t.partition AND c.account_id = t.account_id AND c.region = t.region AND c.trace_id = t.trace_id
    AND (c.completed >= sqlc.arg(receipt_start) OR g.admitted >= sqlc.arg(receipt_start))
    AND c.completed <= sqlc.arg(receipt_end) AND (g.admitted IS NULL OR g.admitted <= sqlc.arg(receipt_end))))
 )
ORDER BY t.start_time DESC, t.trace_id;

-- name: ListSelectedSegments :many
SELECT s.*
FROM xray_traces t
LEFT JOIN xray_group_traces g
 ON g.partition = t.partition AND g.account_id = t.account_id AND g.region = t.region
 AND g.trace_id = t.trace_id AND g.group_id = sqlc.arg(group_id) AND CAST(sqlc.arg(group_id) AS TEXT) <> ''
JOIN xray_segments s
 ON s.partition = t.partition AND s.account_id = t.account_id AND s.region = t.region AND s.trace_id = t.trace_id
WHERE t.partition = sqlc.arg(partition) AND t.account_id = sqlc.arg(account_id) AND t.region = sqlc.arg(region)
 AND (CAST(sqlc.arg(group_id) AS TEXT) = '' OR g.trace_id IS NOT NULL)
 AND (
  (CAST(sqlc.arg(kind) AS INTEGER) = 0 AND t.start_time >= sqlc.arg(start_seconds) AND t.start_time <= sqlc.arg(end_seconds))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 1 AND t.updated >= sqlc.arg(receipt_start) AND t.updated <= sqlc.arg(receipt_end))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 2 AND t.end_time >= sqlc.arg(start_seconds) AND t.start_time <= sqlc.arg(end_seconds))
  OR (CAST(sqlc.arg(kind) AS INTEGER) = 3 AND EXISTS (
   SELECT 1 FROM xray_segments c
   WHERE c.partition = t.partition AND c.account_id = t.account_id AND c.region = t.region AND c.trace_id = t.trace_id
    AND (c.completed >= sqlc.arg(receipt_start) OR g.admitted >= sqlc.arg(receipt_start))
    AND c.completed <= sqlc.arg(receipt_end) AND (g.admitted IS NULL OR g.admitted <= sqlc.arg(receipt_end))))
 )
ORDER BY s.trace_id, s.id;

-- name: DeleteEmptyTrace :exec
DELETE FROM xray_traces
WHERE xray_traces.partition = sqlc.arg(partition) AND xray_traces.account_id = sqlc.arg(account_id) AND xray_traces.region = sqlc.arg(region) AND xray_traces.trace_id = sqlc.arg(trace_id)
 AND NOT EXISTS (SELECT 1 FROM xray_segments s WHERE s.partition = xray_traces.partition AND s.account_id = xray_traces.account_id AND s.region = xray_traces.region AND s.trace_id = xray_traces.trace_id);

-- name: GetGroup :one
SELECT * FROM xray_groups WHERE partition = ? AND account_id = ? AND region = ? AND id = ? AND name = ?;

-- name: ListGroups :many
SELECT * FROM xray_groups WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: PutGroup :exec
INSERT INTO xray_groups (partition, account_id, region, id, name, filter_expression, version)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET
 filter_expression = excluded.filter_expression, version = excluded.version;

-- name: ListGroupTags :many
SELECT key, value FROM xray_group_tags WHERE partition = ? AND account_id = ? AND region = ? AND group_id = ? ORDER BY key;

-- name: ListScopeGroupTags :many
SELECT * FROM xray_group_tags WHERE partition = ? AND account_id = ? AND region = ? ORDER BY group_id, key;

-- name: DeleteGroupTags :exec
DELETE FROM xray_group_tags WHERE partition = ? AND account_id = ? AND region = ? AND group_id = ?;

-- name: PutGroupTag :exec
INSERT INTO xray_group_tags (partition, account_id, region, group_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: AddGroupTrace :execrows
INSERT INTO xray_group_traces (partition, account_id, region, group_id, trace_id, version, admitted, admitted_revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, group_id, trace_id) DO NOTHING;

-- name: DeleteGroup :exec
DELETE FROM xray_groups WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;
