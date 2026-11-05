-- name: GetTableWarehouseObject :one
SELECT * FROM s3tables_objects
WHERE warehouse = ? AND object_key = ?;

-- name: GetTableWarehouseObjectKey :one
SELECT object_key FROM s3tables_objects WHERE warehouse = ? AND object_key = ?;

-- name: PutTableWarehouseObject :exec
INSERT INTO s3tables_objects (warehouse, object_key, etag, size, modified_at, content,
    content_type, cache_control, content_disposition, content_encoding, content_language,
    expires_at, checksum_algorithm, checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_sha1, checksum_sha256,
    encryption_version, encryption_algorithm, encryption_key, encryption_nonce)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteTableWarehouseObject :exec
DELETE FROM s3tables_objects WHERE warehouse = ? AND object_key = ?;

-- name: ListTableWarehouseObjects :many
SELECT object_key, etag, size, modified_at, content_type, cache_control, content_disposition,
    content_encoding, content_language, expires_at, checksum_algorithm,
    checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_sha1, checksum_sha256
FROM s3tables_objects
WHERE warehouse = ? AND object_key >= sqlc.arg(prefix_start) AND object_key < sqlc.arg(prefix_end)
ORDER BY object_key;

-- name: DeleteTableWarehouseObjects :exec
DELETE FROM s3tables_objects WHERE warehouse = ?;

-- name: NextTableWarehouseObjectEncryption :one
SELECT warehouse, object_key, size, content,
    encryption_version, encryption_algorithm, encryption_key, encryption_nonce
FROM s3tables_objects
WHERE encryption_version = 0
ORDER BY warehouse, object_key LIMIT 1;

-- name: EncryptLegacyTableWarehouseObject :exec
UPDATE s3tables_objects SET content = ?, encryption_version = ?, encryption_algorithm = ?,
    encryption_key = ?, encryption_nonce = ?
WHERE warehouse = ? AND object_key = ?;
