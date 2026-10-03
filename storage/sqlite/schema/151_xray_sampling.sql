CREATE TABLE xray_sampling_rules (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 priority INTEGER NOT NULL,
 fixed_rate REAL NOT NULL,
 reservoir_size INTEGER NOT NULL,
 host TEXT NOT NULL,
 http_method TEXT NOT NULL,
 resource_arn TEXT NOT NULL,
 service_name TEXT NOT NULL,
 service_type TEXT NOT NULL,
 url_path TEXT NOT NULL,
 boost_max_rate REAL,
 boost_cooldown_minutes INTEGER,
 created DATETIME NOT NULL,
 modified DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE xray_sampling_attributes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name, key),
 FOREIGN KEY (partition, account_id, region, rule_name)
 REFERENCES xray_sampling_rules(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE xray_sampling_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name, key),
 FOREIGN KEY (partition, account_id, region, rule_name)
 REFERENCES xray_sampling_rules(partition, account_id, region, name) ON DELETE CASCADE
);

-- Default exists without persisted rule configuration. Its SDK clients and
-- reports have the same lifetime and quotas as clients of explicitly stored rules.
CREATE TABLE xray_sampling_clients (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 client_id TEXT NOT NULL,
 first_seen DATETIME NOT NULL,
 last_seen DATETIME NOT NULL,
 quota INTEGER NOT NULL,
 quota_expires DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name, client_id)
);
CREATE INDEX xray_sampling_clients_expiry ON xray_sampling_clients(last_seen);

CREATE TABLE xray_sampling_statistics (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 client_id TEXT NOT NULL,
 window DATETIME NOT NULL,
 timestamp DATETIME NOT NULL,
 received DATETIME NOT NULL,
 request_count INTEGER NOT NULL,
 sampled_count INTEGER NOT NULL,
 borrow_count INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name, client_id, window)
);
CREATE INDEX xray_sampling_statistics_expiry ON xray_sampling_statistics(received);

CREATE TABLE xray_sampling_boost_statistics (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 service_name TEXT NOT NULL,
 window DATETIME NOT NULL,
 timestamp DATETIME NOT NULL,
 received DATETIME NOT NULL,
 total_count INTEGER NOT NULL,
 anomaly_count INTEGER NOT NULL,
 sampled_anomaly_count INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name, service_name, window)
);
CREATE INDEX xray_sampling_boost_statistics_expiry ON xray_sampling_boost_statistics(received);

CREATE TABLE xray_sampling_boosts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 rule_name TEXT NOT NULL,
 rate REAL NOT NULL,
 expires DATETIME NOT NULL,
 triggered DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, rule_name)
);

CREATE TABLE xray_sampling_modifications (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 modified DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region)
);
