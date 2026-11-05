-- Physical table data is private to the S3 Tables owner. Warehouse identities
-- remain reserved after table deletion; these are not ordinary S3 buckets.
CREATE TABLE s3tables_objects (
    warehouse TEXT NOT NULL,
    object_key TEXT NOT NULL,
    etag TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    modified_at TIMESTAMP NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY (warehouse, object_key)
);
