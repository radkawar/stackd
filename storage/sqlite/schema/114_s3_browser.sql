CREATE TABLE s3_cors_rules (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, position INTEGER NOT NULL,
    id TEXT, max_age_seconds INTEGER,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_cors_values (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, rule_position INTEGER NOT NULL,
    kind TEXT NOT NULL, position INTEGER NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, bucket_name, rule_position, kind, position),
    FOREIGN KEY (partition, bucket_name, rule_position) REFERENCES s3_cors_rules(partition, bucket_name, position) ON DELETE CASCADE
);
CREATE TABLE s3_websites (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL,
    index_suffix TEXT, error_key TEXT, redirect_host TEXT, redirect_protocol TEXT,
    PRIMARY KEY (partition, bucket_name),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_buckets(partition, name) ON DELETE CASCADE
);
CREATE TABLE s3_website_rules (
    partition TEXT NOT NULL, bucket_name TEXT NOT NULL, position INTEGER NOT NULL,
    has_condition BOOLEAN NOT NULL, condition_prefix TEXT, condition_error TEXT,
    redirect_host TEXT, redirect_protocol TEXT, redirect_code TEXT,
    replace_key_prefix TEXT, replace_key TEXT,
    PRIMARY KEY (partition, bucket_name, position),
    FOREIGN KEY (partition, bucket_name) REFERENCES s3_websites(partition, bucket_name) ON DELETE CASCADE
);
