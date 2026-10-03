CREATE TABLE lambda_event_source_filter_encryption (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    uuid TEXT NOT NULL,
    key_arn TEXT NOT NULL,
    function_arn TEXT NOT NULL,
    content BLOB NOT NULL,
    data_key BLOB NOT NULL,
    PRIMARY KEY (partition, account, region, uuid),
    FOREIGN KEY (partition, account, region, uuid)
        REFERENCES lambda_event_source_mappings(partition, account, region, uuid) ON DELETE CASCADE
);
