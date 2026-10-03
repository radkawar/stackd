-- name: GetAccessLogDelivery :one
SELECT * FROM s3_access_log_deliveries WHERE id = ?;

-- name: NextAccessLogDelivery :one
SELECT id, due FROM s3_access_log_deliveries ORDER BY due, id COLLATE BINARY LIMIT 1;

-- name: GetAccessLogDeliveryGrants :many
SELECT * FROM s3_access_log_delivery_grants WHERE delivery_id = ? ORDER BY position;

-- name: InsertAccessLogDelivery :execrows
INSERT INTO s3_access_log_deliveries (id, partition, bucket_name, account_id, region, target_bucket, target_prefix, key_format, has_grants, record, at, due)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING;

-- name: UpdateAccessLogDeliveryDue :exec
UPDATE s3_access_log_deliveries SET due = ? WHERE id = ?;

-- name: PutAccessLogDeliveryGrant :exec
INSERT INTO s3_access_log_delivery_grants (delivery_id, position, grantee_type, grantee_id, grantee_uri, permission)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteAccessLogDelivery :exec
DELETE FROM s3_access_log_deliveries WHERE id = ?;
