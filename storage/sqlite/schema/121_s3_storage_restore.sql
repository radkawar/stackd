ALTER TABLE s3_object_versions ADD COLUMN storage_class TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_multipart_uploads ADD COLUMN storage_class TEXT NOT NULL DEFAULT '';

CREATE TABLE s3_object_restores (
    partition TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    object_name TEXT NOT NULL,
    version_id TEXT NOT NULL,
    due TIMESTAMP NOT NULL,
    ongoing BOOLEAN NOT NULL,
    days INTEGER NOT NULL,
    tier TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, object_name, version_id),
    FOREIGN KEY (partition, bucket_name, object_name, version_id)
        REFERENCES s3_object_versions (partition, bucket_name, name, version_id)
        ON DELETE CASCADE
);

CREATE INDEX s3_object_restores_due ON s3_object_restores
    (due, partition, bucket_name, object_name, version_id);
