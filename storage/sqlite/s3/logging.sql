-- name: GetBucketLogging :one
SELECT * FROM s3_bucket_logging WHERE partition = ? AND bucket_name = ?;

-- name: GetBucketLoggingGrants :many
SELECT * FROM s3_bucket_logging_grants WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: DeleteBucketLogging :exec
DELETE FROM s3_bucket_logging WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketLogging :exec
INSERT INTO s3_bucket_logging (partition, bucket_name, target_bucket, target_prefix, key_format, has_grants)
VALUES (?, ?, ?, ?, ?, ?);

-- name: PutBucketLoggingGrant :exec
INSERT INTO s3_bucket_logging_grants (partition, bucket_name, position, grantee_type, grantee_id, grantee_uri, permission)
VALUES (?, ?, ?, ?, ?, ?, ?);
