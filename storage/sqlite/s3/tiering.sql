-- name: GetBucketTieringConfiguration :one
SELECT * FROM s3_bucket_tiering_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: ListBucketTieringConfigurations :many
SELECT * FROM s3_bucket_tiering_configurations
WHERE partition = ? AND bucket_name = ? AND id > sqlc.arg(after)
ORDER BY id LIMIT sqlc.arg(page_limit);

-- name: CountBucketTieringConfigurations :one
SELECT count(*) FROM s3_bucket_tiering_configurations WHERE partition = ? AND bucket_name = ?;

-- name: BucketHasEnabledTiering :one
SELECT EXISTS (SELECT 1 FROM s3_bucket_tiering_configurations WHERE partition = ? AND bucket_name = ? AND enabled);

-- name: PutBucketTieringConfiguration :exec
INSERT INTO s3_bucket_tiering_configurations (
    partition, bucket_name, id, enabled, has_filter, filter_kind, filter_prefix, parent_event_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteBucketTieringConfiguration :exec
DELETE FROM s3_bucket_tiering_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: GetBucketTieringTags :many
SELECT * FROM s3_bucket_tiering_tags
WHERE partition = ? AND bucket_name = ? AND configuration_id = ? ORDER BY position;

-- name: PutBucketTieringTag :exec
INSERT INTO s3_bucket_tiering_tags (partition, bucket_name, configuration_id, position, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBucketTieringRules :many
SELECT * FROM s3_bucket_tiering_rules
WHERE partition = ? AND bucket_name = ? AND configuration_id = ? ORDER BY position;

-- name: PutBucketTieringRule :exec
INSERT INTO s3_bucket_tiering_rules (partition, bucket_name, configuration_id, position, access_tier, days)
VALUES (?, ?, ?, ?, ?, ?);

-- name: NextTieringScan :one
SELECT * FROM s3_bucket_tiering_scans ORDER BY due, partition, bucket_name LIMIT 1;

-- name: PutTieringScan :exec
INSERT INTO s3_bucket_tiering_scans (partition, bucket_name, due)
VALUES (?, ?, ?)
ON CONFLICT (partition, bucket_name) DO UPDATE SET due = excluded.due;

-- name: DeleteTieringScan :exec
DELETE FROM s3_bucket_tiering_scans WHERE partition = ? AND bucket_name = ?;

-- name: SetObjectTiering :exec
UPDATE s3_object_versions SET tiering_accessed = sqlc.narg(tiering_accessed), archive_tier = sqlc.arg(archive_tier)
WHERE partition = sqlc.arg(partition) AND bucket_name = sqlc.arg(bucket_name) AND name = sqlc.arg(name)
AND version_id = sqlc.arg(version_id) AND created_order = sqlc.arg(created_order)
AND (sqlc.narg(tiering_accessed) IS NULL OR storage_class = 'INTELLIGENT_TIERING');
