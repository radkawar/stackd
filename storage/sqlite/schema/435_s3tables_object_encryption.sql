-- Version zero identifies pre-encryption rows only during the eager factory migration.
-- New writes always retain a local AES-256 key and a separately typed GCM nonce.
ALTER TABLE s3tables_objects ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3tables_objects ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE s3tables_objects ADD COLUMN encryption_key BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3tables_objects ADD COLUMN encryption_nonce BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3tables_multipart_parts ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE s3tables_multipart_parts ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE s3tables_multipart_parts ADD COLUMN encryption_key BLOB NOT NULL DEFAULT X'';
ALTER TABLE s3tables_multipart_parts ADD COLUMN encryption_nonce BLOB NOT NULL DEFAULT X'';

-- Successful conversions leave these small indexes, so normal reopen never
-- scans encrypted BLOBs and eager migration remains one-row-at-a-time.
CREATE INDEX s3tables_objects_legacy_encryption
    ON s3tables_objects (warehouse, object_key) WHERE encryption_version = 0;
CREATE INDEX s3tables_parts_legacy_encryption
    ON s3tables_multipart_parts (warehouse, object_key, upload_id, part_number)
    WHERE encryption_version = 0;
