-- name: GetBucketCORSRules :many
SELECT * FROM s3_cors_rules WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: GetBucketCORSValues :many
SELECT * FROM s3_cors_values WHERE partition = ? AND bucket_name = ? ORDER BY rule_position, kind, position;

-- name: DeleteBucketCORS :exec
DELETE FROM s3_cors_rules WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketCORSRule :exec
INSERT INTO s3_cors_rules (partition, bucket_name, position, id, max_age_seconds) VALUES (?, ?, ?, ?, ?);

-- name: PutBucketCORSValue :exec
INSERT INTO s3_cors_values (partition, bucket_name, rule_position, kind, position, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBucketWebsite :one
SELECT * FROM s3_websites WHERE partition = ? AND bucket_name = ?;

-- name: GetBucketWebsiteRules :many
SELECT * FROM s3_website_rules WHERE partition = ? AND bucket_name = ? ORDER BY position;

-- name: DeleteBucketWebsite :exec
DELETE FROM s3_websites WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketWebsite :exec
INSERT INTO s3_websites (partition, bucket_name, index_suffix, error_key, redirect_host, redirect_protocol) VALUES (?, ?, ?, ?, ?, ?);

-- name: PutBucketWebsiteRule :exec
INSERT INTO s3_website_rules (partition, bucket_name, position, has_condition, condition_prefix, condition_error,
    redirect_host, redirect_protocol, redirect_code, replace_key_prefix, replace_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
