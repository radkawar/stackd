-- name: GetTableWarehouseObjectInfo :one
SELECT object_key, etag, size, modified_at, content_type, cache_control, content_disposition,
    content_encoding, content_language, expires_at, checksum_algorithm,
    checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_sha1, checksum_sha256
FROM s3tables_objects
WHERE warehouse = ? AND object_key = ?;
