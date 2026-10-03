-- name: GetBucketMetricsConfiguration :one
SELECT * FROM s3_bucket_metrics_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: ListBucketMetricsConfigurations :many
WITH selected AS (
    SELECT base.partition, base.bucket_name, base.id FROM s3_bucket_metrics_configurations base
    WHERE base.partition = sqlc.arg(partition) AND base.bucket_name = sqlc.arg(bucket_name) AND base.id > sqlc.arg(after)
    ORDER BY base.id LIMIT sqlc.arg(page_limit)
)
SELECT sqlc.embed(c), t.position AS tag_position, t.key AS tag_key, t.value AS tag_value
FROM s3_bucket_metrics_configurations c
JOIN selected s ON s.partition = c.partition AND s.bucket_name = c.bucket_name AND s.id = c.id
LEFT JOIN s3_bucket_metrics_tags t
ON t.partition = c.partition AND t.bucket_name = c.bucket_name AND t.configuration_id = c.id
ORDER BY c.id, t.position;

-- name: CountBucketMetricsConfigurations :one
SELECT count(*) FROM s3_bucket_metrics_configurations WHERE partition = ? AND bucket_name = ?;

-- name: PutBucketMetricsConfiguration :exec
INSERT INTO s3_bucket_metrics_configurations (partition, bucket_name, id, filter_kind, filter_prefix, access_point_arn)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteBucketMetricsConfiguration :exec
DELETE FROM s3_bucket_metrics_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: GetBucketMetricsTags :many
SELECT * FROM s3_bucket_metrics_tags
WHERE partition = ? AND bucket_name = ? AND configuration_id = ? ORDER BY position;

-- name: PutBucketMetricsTag :exec
INSERT INTO s3_bucket_metrics_tags (partition, bucket_name, configuration_id, position, key, value)
VALUES (?, ?, ?, ?, ?, ?);
