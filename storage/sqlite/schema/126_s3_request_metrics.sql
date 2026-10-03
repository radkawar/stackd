CREATE TABLE s3_bucket_metrics_configurations (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, id TEXT NOT NULL,
    filter_kind TEXT, filter_prefix TEXT, access_point_arn TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);

CREATE TABLE s3_bucket_metrics_tags (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, configuration_id TEXT NOT NULL,
    position INTEGER NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, configuration_id, position),
    FOREIGN KEY (partition, bucket_name, configuration_id) REFERENCES s3_bucket_metrics_configurations(partition, bucket_name, id) ON DELETE CASCADE
);
