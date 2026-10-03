-- name: NextReplicationMetricPublication :one
SELECT * FROM s3_replication_metric_publications
ORDER BY CASE WHEN recurring = false AND ready_at > at THEN ready_at ELSE at END,
    at, partition COLLATE BINARY, bucket_name COLLATE BINARY,
    destination_partition COLLATE BINARY, destination_bucket COLLATE BINARY,
    account_id COLLATE BINARY, source_region COLLATE BINARY,
    destination_region COLLATE BINARY, rule_id COLLATE BINARY
LIMIT 1;

-- name: GetReplicationMetricPublication :one
SELECT * FROM s3_replication_metric_publications
WHERE partition = ? AND bucket_name = ? AND destination_partition = ? AND destination_bucket = ?
    AND account_id = ? AND source_region = ? AND destination_region = ? AND rule_id = ? AND at = ?;

-- name: StopReplicationMetricSchedules :exec
UPDATE s3_replication_metric_publications SET recurring = false
WHERE partition = ? AND bucket_name = ? AND recurring = true;

-- name: DeleteInactiveReplicationMetricSchedules :exec
DELETE FROM s3_replication_metric_publications
WHERE partition = ? AND bucket_name = ? AND recurring = false AND sampled = false AND operations = 0;

-- name: ActivateReplicationMetricSchedule :exec
INSERT INTO s3_replication_metric_publications (partition, bucket_name,
    destination_partition, destination_bucket, account_id, source_region, destination_region,
    rule_id, at, ready_at, operations, failed, recurring)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, true)
ON CONFLICT (partition, bucket_name, destination_partition, destination_bucket,
    account_id, source_region, destination_region, rule_id, at)
DO UPDATE SET recurring = NOT s3_replication_metric_publications.sampled,
    ready_at = CASE
        WHEN s3_replication_metric_publications.sampled = false AND s3_replication_metric_publications.operations = 0
        THEN excluded.ready_at ELSE s3_replication_metric_publications.ready_at END;

-- name: AddReplicationMetricOutcome :exec
INSERT INTO s3_replication_metric_publications (partition, bucket_name,
    destination_partition, destination_bucket, account_id, source_region, destination_region,
    rule_id, at, ready_at, operations, failed, recurring)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, false)
ON CONFLICT (partition, bucket_name, destination_partition, destination_bucket,
    account_id, source_region, destination_region, rule_id, at)
DO UPDATE SET operations = s3_replication_metric_publications.operations + 1,
    failed = s3_replication_metric_publications.failed + excluded.failed;

-- name: SampleReplicationMetricPublication :one
UPDATE s3_replication_metric_publications
SET recurring = false, sampled = true, pending_operations = ?, pending_bytes = ?, pending_oldest = ?
WHERE partition = ? AND bucket_name = ? AND destination_partition = ? AND destination_bucket = ?
    AND account_id = ? AND source_region = ? AND destination_region = ? AND rule_id = ? AND at = ?
    AND recurring = true
RETURNING ready_at;

-- name: DeleteReplicationMetricPublication :exec
DELETE FROM s3_replication_metric_publications
WHERE partition = ? AND bucket_name = ? AND destination_partition = ? AND destination_bucket = ?
    AND account_id = ? AND source_region = ? AND destination_region = ? AND rule_id = ? AND at = ?;

-- name: GetReplicationPendingCounts :one
SELECT COUNT(*) AS operations,
    CAST(COALESCE(SUM(CASE WHEN jobs.operation = 'OBJECT_PUT' THEN source.size ELSE 0 END), 0) AS INTEGER) AS bytes
FROM s3_replication_jobs AS jobs
JOIN s3_buckets AS buckets ON buckets.partition = jobs.partition AND buckets.name = jobs.bucket_name
JOIN s3_object_versions AS source ON source.partition = jobs.partition AND source.bucket_name = jobs.bucket_name
    AND source.name = jobs.object_name AND source.version_id = jobs.version_id
WHERE jobs.partition = sqlc.arg(partition) AND jobs.bucket_name = sqlc.arg(bucket_name)
    AND jobs.destination_partition = sqlc.arg(destination_partition) AND jobs.destination_bucket = sqlc.arg(destination_bucket)
    AND jobs.rule_id = sqlc.arg(rule_id) AND buckets.account_id = sqlc.arg(account_id)
    AND jobs.created <= sqlc.arg(at);

-- name: GetOldestReplicationPending :one
SELECT jobs.created
FROM s3_replication_jobs AS jobs
JOIN s3_buckets AS buckets ON buckets.partition = jobs.partition AND buckets.name = jobs.bucket_name
WHERE jobs.partition = sqlc.arg(partition) AND jobs.bucket_name = sqlc.arg(bucket_name)
    AND jobs.destination_partition = sqlc.arg(destination_partition) AND jobs.destination_bucket = sqlc.arg(destination_bucket)
    AND jobs.rule_id = sqlc.arg(rule_id) AND buckets.account_id = sqlc.arg(account_id)
    AND jobs.created <= sqlc.arg(at)
ORDER BY jobs.created, jobs.sequence LIMIT 1;
