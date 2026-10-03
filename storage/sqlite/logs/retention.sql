-- name: NextRetention :one
SELECT CAST(coalesce(min((SELECT min(timestamp) FROM logs_events e WHERE e.group_id = g.id) + g.retention_days * 86400000 + 1), -1) AS INTEGER) AS expires
FROM logs_groups g WHERE g.retention_days > 0;

-- name: ExpiringStreams :many
SELECT s.id, CAST(sqlc.arg(now_millis) - g.retention_days * 86400000 AS INTEGER) AS cutoff
FROM logs_streams s JOIN logs_groups g ON g.id = s.group_id
WHERE g.retention_days > 0 AND EXISTS (
 SELECT 1 FROM logs_events e WHERE e.stream_id = s.id AND e.timestamp < sqlc.arg(now_millis) - g.retention_days * 86400000
) ORDER BY s.id;

-- name: DeleteExpiredEvents :exec
DELETE FROM logs_events WHERE stream_id = ? AND timestamp < ?;

-- name: RefreshRetainedStream :exec
UPDATE logs_streams SET (event_count, first_event, last_event) = (
 SELECT count(*), coalesce(min(timestamp), 0), coalesce(max(timestamp), 0) FROM logs_events WHERE stream_id = logs_streams.id
) WHERE id = ?;
