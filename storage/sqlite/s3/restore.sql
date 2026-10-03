-- name: GetObjectRestore :one
SELECT * FROM s3_object_restores
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;

-- name: NextObjectRestore :one
SELECT * FROM s3_object_restores
ORDER BY due, partition COLLATE BINARY, bucket_name COLLATE BINARY, object_name COLLATE BINARY, version_id COLLATE BINARY
LIMIT 1;

-- name: PutObjectRestore :exec
INSERT INTO s3_object_restores (partition, bucket_name, object_name, version_id, due, ongoing, days, tier, parent_event_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, bucket_name, object_name, version_id) DO UPDATE SET
    due = excluded.due, ongoing = excluded.ongoing, days = excluded.days,
    tier = excluded.tier, parent_event_id = excluded.parent_event_id;

-- name: DeleteObjectRestore :exec
DELETE FROM s3_object_restores
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?;
