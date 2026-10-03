CREATE TABLE s3_bucket_inventory_configurations (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL, all_versions BOOLEAN NOT NULL, weekly BOOLEAN NOT NULL,
    filter_prefix TEXT, optional_fields_present BOOLEAN NOT NULL,
    destination_bucket_arn TEXT NOT NULL, destination_account_id TEXT, destination_prefix TEXT,
    format TEXT NOT NULL, encryption TEXT NOT NULL, kms_key_id TEXT NOT NULL,
    parent_event_id TEXT NOT NULL, next_report TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, bucket_name, id),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE INDEX s3_bucket_inventory_due ON s3_bucket_inventory_configurations(next_report, partition, bucket_name, id)
    WHERE enabled = 1;

CREATE TABLE s3_bucket_inventory_optional_fields (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, configuration_id TEXT NOT NULL,
    position INTEGER NOT NULL, field TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, configuration_id, position),
    FOREIGN KEY (partition, bucket_name, configuration_id) REFERENCES s3_bucket_inventory_configurations(partition, bucket_name, id) ON DELETE CASCADE
);
