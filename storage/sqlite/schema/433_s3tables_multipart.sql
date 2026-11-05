-- Pending uploads and actual part bytes are private typed physical records.
CREATE TABLE s3tables_multipart_uploads (
    warehouse TEXT NOT NULL,
    object_key TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    content_type TEXT NOT NULL,
    cache_control TEXT NOT NULL,
    content_disposition TEXT NOT NULL,
    content_encoding TEXT NOT NULL,
    content_language TEXT NOT NULL,
    expires_at TIMESTAMP,
    checksum_algorithm TEXT NOT NULL,
    PRIMARY KEY (warehouse, object_key, upload_id)
);
CREATE TABLE s3tables_multipart_parts (
    warehouse TEXT NOT NULL,
    object_key TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    etag TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0 AND size <= 5368709120),
    modified_at TIMESTAMP NOT NULL,
    checksum_crc32 TEXT NOT NULL,
    checksum_crc32c TEXT NOT NULL,
    checksum_sha1 TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY (warehouse, object_key, upload_id, part_number),
    FOREIGN KEY (warehouse, object_key, upload_id)
        REFERENCES s3tables_multipart_uploads (warehouse, object_key, upload_id) ON DELETE CASCADE
);
