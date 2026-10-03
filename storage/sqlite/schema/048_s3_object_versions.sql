ALTER TABLE s3_buckets ADD COLUMN versioning TEXT NOT NULL DEFAULT '';

CREATE TABLE s3_object_version_sequence (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 0 AND typeof(sequence) = 'integer')
);
INSERT INTO s3_object_version_sequence (singleton, sequence) SELECT 1, count(*) FROM s3_objects;

CREATE TABLE s3_object_versions (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    name TEXT NOT NULL COLLATE BINARY,
    version_id TEXT NOT NULL CHECK (version_id <> ''),
    sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
    delete_marker BOOLEAN NOT NULL,
    modified TIMESTAMP NOT NULL,
    size INTEGER NOT NULL,
    etag TEXT NOT NULL,
    checksum_algorithm TEXT NOT NULL, checksum TEXT NOT NULL,
    content_type TEXT NOT NULL, content_encoding TEXT NOT NULL, content_language TEXT NOT NULL,
    content_disposition TEXT NOT NULL, cache_control TEXT NOT NULL,
    expires TIMESTAMP,
    PRIMARY KEY (partition, bucket_name, name, version_id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_object_versions_history ON s3_object_versions(partition, bucket_name, name COLLATE BINARY, sequence DESC);
CREATE TABLE s3_object_version_metadata (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id, key),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);
CREATE TABLE s3_object_version_data (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, object_name TEXT NOT NULL, version_id TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id),
    FOREIGN KEY (partition, bucket_name, object_name, version_id) REFERENCES s3_object_versions(partition, bucket_name, name, version_id) ON DELETE CASCADE
);

INSERT INTO s3_object_versions (
    partition, bucket_name, name, version_id, sequence, delete_marker, modified, size, etag,
    checksum_algorithm, checksum, content_type, content_encoding, content_language, content_disposition, cache_control, expires
)
SELECT partition, bucket_name, name, 'null', row_number() OVER (ORDER BY partition, bucket_name, name COLLATE BINARY),
    false, modified, size, etag, checksum_algorithm, checksum, content_type, content_encoding, content_language, content_disposition, cache_control, expires
FROM s3_objects;
INSERT INTO s3_object_version_metadata (partition, bucket_name, object_name, version_id, key, value)
SELECT partition, bucket_name, object_name, 'null', key, value FROM s3_object_metadata;
INSERT INTO s3_object_version_data (partition, bucket_name, object_name, version_id, encryption_key, ciphertext)
SELECT partition, bucket_name, object_name, 'null', encryption_key, ciphertext FROM s3_object_data;

DROP TABLE s3_object_data;
DROP TABLE s3_object_metadata;
DROP TABLE s3_objects;
