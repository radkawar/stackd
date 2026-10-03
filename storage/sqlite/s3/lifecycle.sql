-- name: GetBucketLifecycle :one
SELECT * FROM s3_bucket_lifecycle WHERE partition = ? AND bucket_name = ?;

-- name: NextLifecycleScan :one
SELECT partition, bucket_name, next_scan FROM s3_bucket_lifecycle
WHERE next_scan IS NOT NULL ORDER BY next_scan, partition, bucket_name LIMIT 1;

-- name: AdvanceLifecycleScan :exec
UPDATE s3_bucket_lifecycle SET next_scan = ? WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketLifecycle :exec
INSERT INTO s3_bucket_lifecycle (partition, bucket_name, minimum_object_size, next_scan, parent_event_id)
VALUES (?, ?, ?, ?, ?);

-- name: DeleteBucketLifecycle :exec
DELETE FROM s3_bucket_lifecycle WHERE partition = ? AND bucket_name = ?;

-- name: GetBucketLifecycleRules :many
SELECT * FROM s3_bucket_lifecycle_rules WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: PutBucketLifecycleRule :exec
INSERT INTO s3_bucket_lifecycle_rules (
    partition, bucket_name, position, id, enabled, filter_kind, filter_prefix,
    object_size_greater_than, object_size_less_than, expiration_date, expiration_days,
    expired_object_delete_marker, noncurrent_expiration_days, noncurrent_expiration_newer_versions, abort_incomplete_days)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetBucketLifecycleTags :many
SELECT * FROM s3_bucket_lifecycle_tags WHERE partition = ? AND bucket_name = ? ORDER BY rule_position, position;

-- name: PutBucketLifecycleTag :exec
INSERT INTO s3_bucket_lifecycle_tags (partition, bucket_name, rule_position, position, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBucketLifecycleTransitions :many
SELECT * FROM s3_bucket_lifecycle_transitions WHERE partition = ? AND bucket_name = ? ORDER BY rule_position, noncurrent, position;

-- name: PutBucketLifecycleTransition :exec
INSERT INTO s3_bucket_lifecycle_transitions (partition, bucket_name, rule_position, noncurrent, position, date, days, storage_class, newer_noncurrent_versions)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TransitionObject :execrows
UPDATE s3_object_versions SET storage_class = ?, sequence = ?
WHERE partition = ? AND bucket_name = ? AND name = ? AND version_id = ?;
