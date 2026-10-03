-- name: GetReplicationStates :many
SELECT * FROM s3_replication_states
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?
ORDER BY destination_partition COLLATE BINARY, destination_bucket COLLATE BINARY, operation COLLATE BINARY;

-- name: PutReplicationState :exec
INSERT INTO s3_replication_states (partition, bucket_name, object_name, version_id,
    destination_partition, destination_bucket, operation, sequence, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, bucket_name, object_name, version_id, destination_partition, destination_bucket, operation)
DO UPDATE SET sequence = excluded.sequence, status = excluded.status
WHERE excluded.sequence >= s3_replication_states.sequence;

-- name: GetReplicationJob :one
SELECT * FROM s3_replication_jobs WHERE sequence = ?;

-- name: ReplicationJobsForVersion :many
SELECT * FROM s3_replication_jobs
WHERE partition = ? AND bucket_name = ? AND object_name = ? AND version_id = ?
ORDER BY sequence;

-- name: NextReplicationAttempt :one
SELECT * FROM s3_replication_jobs ORDER BY due, sequence LIMIT 1;

-- name: NextReplicationThreshold :one
SELECT * FROM s3_replication_jobs
WHERE time_status = 'Enabled' AND threshold_reported = false
ORDER BY created, sequence LIMIT 1;

-- name: PutReplicationJob :exec
INSERT INTO s3_replication_jobs (sequence, partition, bucket_name, object_name, version_id,
    destination_partition, destination_bucket, destination_region, account_id, owner_override,
    storage_class, kms_key_id, metrics_status, metrics_minutes, metrics_ready_at, time_status, time_minutes,
    operation, role_arn, rule_id, parent_event_id, created, due, attempts, threshold_reported)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (sequence) DO UPDATE SET due = excluded.due, attempts = excluded.attempts,
    threshold_reported = excluded.threshold_reported;

-- name: DeleteReplicationJob :exec
DELETE FROM s3_replication_jobs WHERE sequence = ?;

-- name: CopyReplicaData :execrows
INSERT INTO s3_object_version_data (partition, bucket_name, object_name, version_id, encryption_key, ciphertext,
    customer_key_salt, customer_key_hash, customer_key_md5)
SELECT CAST(sqlc.arg(destination_partition) AS TEXT), CAST(sqlc.arg(destination_bucket) AS TEXT),
    CAST(sqlc.arg(destination_name) AS TEXT), CAST(sqlc.arg(destination_version_id) AS TEXT),
    CAST(sqlc.arg(encryption_key) AS BLOB), source.ciphertext,
    CAST(sqlc.arg(customer_key_salt) AS BLOB), CAST(sqlc.arg(customer_key_hash) AS BLOB),
    CAST(sqlc.arg(customer_key_md5) AS TEXT)
FROM s3_object_version_data AS source
WHERE source.partition = sqlc.arg(source_partition) AND source.bucket_name = sqlc.arg(source_bucket)
    AND source.object_name = sqlc.arg(source_name) AND source.version_id = sqlc.arg(source_version_id);

-- name: CopyReplicaParts :exec
INSERT INTO s3_encrypted_parts (partition, bucket_name, object_name, version_id, number, modified, size, etag, checksum, ciphertext)
SELECT CAST(sqlc.arg(destination_partition) AS TEXT), CAST(sqlc.arg(destination_bucket) AS TEXT),
    CAST(sqlc.arg(destination_name) AS TEXT), CAST(sqlc.arg(destination_version_id) AS TEXT),
    source.number, source.modified, source.size, source.etag, source.checksum, source.ciphertext
FROM s3_encrypted_parts AS source
WHERE source.partition = sqlc.arg(source_partition) AND source.bucket_name = sqlc.arg(source_bucket)
    AND source.object_name = sqlc.arg(source_name) AND source.version_id = CAST(sqlc.arg(source_version_id) AS TEXT);
