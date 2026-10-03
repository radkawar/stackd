-- name: GetBucketReplication :one
SELECT * FROM s3_bucket_replication WHERE partition = ? AND bucket_name = ?;

-- name: GetBucketReplicationRules :many
SELECT * FROM s3_replication_rules WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: GetBucketReplicationFilterTags :many
SELECT * FROM s3_replication_filter_tags WHERE partition = ? AND bucket_name = ? ORDER BY rule_position, position;

-- name: DeleteBucketReplication :exec
DELETE FROM s3_bucket_replication WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketReplication :exec
INSERT INTO s3_bucket_replication (partition, bucket_name, role_arn) VALUES (?, ?, ?);

-- name: PutBucketReplicationRule :exec
INSERT INTO s3_replication_rules (partition, bucket_name, position, id, priority, enabled,
    filter_kind, filter_prefix, delete_marker_replication, sse_kms_objects, replica_modifications,
    destination_partition, destination_bucket, destination_region, account_id, owner_override, storage_class, kms_key_id,
    metrics_status, metrics_minutes, metrics_ready_at, time_status, time_minutes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PutBucketReplicationFilterTag :exec
INSERT INTO s3_replication_filter_tags (partition, bucket_name, rule_position, position, key, value)
VALUES (?, ?, ?, ?, ?, ?);
