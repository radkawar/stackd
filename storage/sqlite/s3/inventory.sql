-- name: GetBucketInventoryConfiguration :one
SELECT * FROM s3_bucket_inventory_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: ListBucketInventoryConfigurations :many
WITH selected AS (
    SELECT base.partition, base.bucket_name, base.id FROM s3_bucket_inventory_configurations base
    WHERE base.partition = sqlc.arg(partition) AND base.bucket_name = sqlc.arg(bucket_name) AND base.id > sqlc.arg(after)
    ORDER BY base.id LIMIT sqlc.arg(page_limit)
)
SELECT sqlc.embed(c), f.position AS field_position, f.field AS optional_field
FROM s3_bucket_inventory_configurations c
JOIN selected s ON s.partition = c.partition AND s.bucket_name = c.bucket_name AND s.id = c.id
LEFT JOIN s3_bucket_inventory_optional_fields f
ON f.partition = c.partition AND f.bucket_name = c.bucket_name AND f.configuration_id = c.id
ORDER BY c.id, f.position;

-- name: CountBucketInventoryConfigurations :one
SELECT count(*) FROM s3_bucket_inventory_configurations WHERE partition = ? AND bucket_name = ?;

-- name: NextInventoryConfiguration :one
SELECT * FROM s3_bucket_inventory_configurations
WHERE enabled = 1 ORDER BY next_report, partition, bucket_name, id LIMIT 1;

-- name: PutBucketInventoryConfiguration :exec
INSERT INTO s3_bucket_inventory_configurations (
    partition, bucket_name, id, enabled, all_versions, weekly, filter_prefix, optional_fields_present,
    destination_bucket_arn, destination_account_id, destination_prefix, format, encryption, kms_key_id,
    parent_event_id, next_report)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteBucketInventoryConfiguration :exec
DELETE FROM s3_bucket_inventory_configurations WHERE partition = ? AND bucket_name = ? AND id = ?;

-- name: GetBucketInventoryOptionalFields :many
SELECT * FROM s3_bucket_inventory_optional_fields
WHERE partition = ? AND bucket_name = ? AND configuration_id = ? ORDER BY position;

-- name: PutBucketInventoryOptionalField :exec
INSERT INTO s3_bucket_inventory_optional_fields (partition, bucket_name, configuration_id, position, field)
VALUES (?, ?, ?, ?, ?);

-- name: AdvanceInventoryReport :exec
UPDATE s3_bucket_inventory_configurations SET next_report = sqlc.arg(next_report)
WHERE partition = sqlc.arg(partition) AND bucket_name = sqlc.arg(bucket_name) AND id = sqlc.arg(id)
    AND enabled = 1 AND parent_event_id = sqlc.arg(parent_event_id) AND next_report = sqlc.arg(previous_report);
