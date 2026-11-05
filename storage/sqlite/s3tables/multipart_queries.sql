-- name: CreateTableMultipartUpload :exec
INSERT INTO s3tables_multipart_uploads (warehouse, object_key, upload_id, created_at,
    content_type, cache_control, content_disposition, content_encoding, content_language, expires_at, checksum_algorithm)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetTableMultipartUpload :one
SELECT * FROM s3tables_multipart_uploads WHERE warehouse = ? AND object_key = ? AND upload_id = ?;

-- name: PutTableMultipartPart :exec
INSERT INTO s3tables_multipart_parts (warehouse, object_key, upload_id, part_number, etag, size, modified_at,
    checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_sha1, checksum_sha256, content,
    encryption_version, encryption_algorithm, encryption_key, encryption_nonce)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (warehouse, object_key, upload_id, part_number) DO UPDATE SET
    etag = excluded.etag, size = excluded.size, modified_at = excluded.modified_at,
    checksum_crc32 = excluded.checksum_crc32, checksum_crc32c = excluded.checksum_crc32c,
    checksum_crc64nvme = excluded.checksum_crc64nvme,
    checksum_sha1 = excluded.checksum_sha1, checksum_sha256 = excluded.checksum_sha256, content = excluded.content,
    encryption_version = excluded.encryption_version, encryption_algorithm = excluded.encryption_algorithm,
    encryption_key = excluded.encryption_key, encryption_nonce = excluded.encryption_nonce;

-- name: ListTableMultipartParts :many
SELECT part_number, etag, size, modified_at, checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_sha1, checksum_sha256
FROM s3tables_multipart_parts WHERE warehouse = ? AND object_key = ? AND upload_id = ? ORDER BY part_number;

-- name: GetTableMultipartPart :one
SELECT * FROM s3tables_multipart_parts
WHERE warehouse = ? AND object_key = ? AND upload_id = ? AND part_number = ?;

-- name: DeleteTableMultipartUpload :exec
DELETE FROM s3tables_multipart_uploads WHERE warehouse = ? AND object_key = ? AND upload_id = ?;

-- name: DeleteTableMultipartUploads :exec
DELETE FROM s3tables_multipart_uploads WHERE warehouse = ?;

-- name: NextTableMultipartPartEncryption :one
SELECT warehouse, object_key, upload_id, part_number, size, content,
    encryption_version, encryption_algorithm, encryption_key, encryption_nonce
FROM s3tables_multipart_parts
WHERE encryption_version = 0
ORDER BY warehouse, object_key, upload_id, part_number LIMIT 1;

-- name: EncryptLegacyTableMultipartPart :exec
UPDATE s3tables_multipart_parts SET content = ?, encryption_version = ?, encryption_algorithm = ?,
    encryption_key = ?, encryption_nonce = ?
WHERE warehouse = ? AND object_key = ? AND upload_id = ? AND part_number = ?;
