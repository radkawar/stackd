-- Flow-log admissions and the native capture checkpoint outlive subscription deletion.
-- Unsigned counters use ordered eight-byte BLOBs, matching other EC2 counters.
CREATE TABLE ec2_flow_logs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 selector_resource_id TEXT NOT NULL,
 resource_type TEXT NOT NULL,
 traffic_type TEXT NOT NULL,
 destination_type TEXT NOT NULL,
 destination TEXT NOT NULL,
 log_group_name TEXT NOT NULL,
 permission_arn TEXT NOT NULL,
 log_format TEXT NOT NULL,
 format_version INTEGER NOT NULL,
 aggregation_seconds INTEGER NOT NULL,
 hive_partitions BOOLEAN NOT NULL,
 hour_partitions BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 created_at DATETIME NOT NULL,
 status TEXT NOT NULL,
 delivery_status TEXT NOT NULL,
 delivery_error TEXT NOT NULL,
 capture_error TEXT NOT NULL,
 version BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);

CREATE TABLE ec2_flow_log_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_flow_logs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_flow_log_tokens (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 fingerprint TEXT NOT NULL,
 results_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, token)
);

CREATE TABLE ec2_flow_log_token_results (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 position INTEGER NOT NULL,
 selector_resource_id TEXT NOT NULL,
 flow_log_id TEXT NOT NULL,
 error_code TEXT NOT NULL,
 error_message TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, token, position),
 FOREIGN KEY (partition, account_id, region, token) REFERENCES ec2_flow_log_tokens (partition, account_id, region, token) ON DELETE CASCADE
);

CREATE TABLE ec2_flow_log_capture (
 singleton INTEGER NOT NULL CHECK (singleton = 1),
 cursor TEXT NOT NULL,
 due DATETIME NOT NULL,
 version BLOB NOT NULL,
 PRIMARY KEY (singleton)
);

CREATE TABLE ec2_flow_log_aggregates (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 flow_log_id TEXT NOT NULL,
 aggregate_id TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 interface_partition TEXT NOT NULL,
 interface_account_id TEXT NOT NULL,
 interface_region TEXT NOT NULL,
 interface_id TEXT NOT NULL,
 interface_incarnation TEXT NOT NULL,
 network_id TEXT NOT NULL,
 address TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 subnet_id TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 availability_zone_id TEXT NOT NULL,
 source_address TEXT NOT NULL,
 destination_address TEXT NOT NULL,
 source_port INTEGER NOT NULL,
 destination_port INTEGER NOT NULL,
 protocol INTEGER NOT NULL,
 action TEXT NOT NULL,
 direction TEXT NOT NULL,
 packets BLOB NOT NULL,
 bytes BLOB NOT NULL,
 start DATETIME NOT NULL,
 end DATETIME NOT NULL,
 due DATETIME NOT NULL,
 tcp_flags INTEGER NOT NULL,
 lost BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, flow_log_id, aggregate_id),
 FOREIGN KEY (partition, account_id, region, flow_log_id) REFERENCES ec2_flow_logs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_flow_log_deliveries (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 flow_log_id TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 destination_type TEXT NOT NULL,
 destination TEXT NOT NULL,
 log_group_name TEXT NOT NULL,
 permission_arn TEXT NOT NULL,
 hive_partitions BOOLEAN NOT NULL,
 hour_partitions BOOLEAN NOT NULL,
 header TEXT NOT NULL,
 lines_present BOOLEAN NOT NULL,
 window_start DATETIME NOT NULL,
 due DATETIME NOT NULL,
 version BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id),
 FOREIGN KEY (partition, account_id, region, flow_log_id) REFERENCES ec2_flow_logs (partition, account_id, region, resource_id) ON DELETE CASCADE
);

CREATE TABLE ec2_flow_log_delivery_lines (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 start DATETIME NOT NULL,
 interface_id TEXT NOT NULL,
 message TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_flow_log_deliveries (partition, account_id, region, resource_id) ON DELETE CASCADE
);

