-- name: GetBucketAnalyticsConfiguration :one
SELECT * FROM s3_bucket_analytics_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: ListBucketAnalyticsConfigurations :many
WITH selected AS (
    SELECT base.partition, base.bucket_name, base.id FROM s3_bucket_analytics_configurations base
    WHERE base.partition = sqlc.arg(partition) AND base.bucket_name = sqlc.arg(bucket_name) AND base.id > sqlc.arg(after)
    ORDER BY base.id LIMIT sqlc.arg(page_limit)
)
SELECT sqlc.embed(c), t.position AS tag_position, t.key AS tag_key, t.value AS tag_value
FROM s3_bucket_analytics_configurations c
JOIN selected s ON s.partition = c.partition AND s.bucket_name = c.bucket_name AND s.id = c.id
LEFT JOIN s3_bucket_analytics_tags t
ON t.partition = c.partition AND t.bucket_name = c.bucket_name AND t.configuration_id = c.id
ORDER BY c.id, t.position;

-- name: CountBucketAnalyticsConfigurations :one
SELECT count(*) FROM s3_bucket_analytics_configurations WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketAnalyticsConfiguration :exec
INSERT INTO s3_bucket_analytics_configurations (
    partition, bucket_name, id, filter_kind, filter_prefix,
    destination_bucket_arn, destination_account_id, destination_prefix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteBucketAnalyticsConfiguration :exec
DELETE FROM s3_bucket_analytics_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: GetBucketAnalyticsTags :many
SELECT * FROM s3_bucket_analytics_tags
WHERE partition = ? AND bucket_name = ? AND configuration_id = ? ORDER BY position;

-- name: PutBucketAnalyticsTag :exec
INSERT INTO s3_bucket_analytics_tags (partition, bucket_name, configuration_id, position, key, value)
VALUES (?, ?, ?, ?, ?, ?);
