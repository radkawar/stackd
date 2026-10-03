CREATE TABLE xray_segments (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 trace_id TEXT NOT NULL,
 id TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 subsegment BOOLEAN NOT NULL,
 inline_order INTEGER NOT NULL,
 start_time REAL NOT NULL,
 end_time REAL,
 in_progress BOOLEAN NOT NULL,
 document TEXT NOT NULL,
 received DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, trace_id, id)
);
CREATE INDEX xray_segments_retention ON xray_segments(received);

CREATE TABLE xray_resource_policies (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 document TEXT NOT NULL,
 revision INTEGER NOT NULL,
 updated DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE xray_policy_principals (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 policy_name TEXT NOT NULL,
 arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, policy_name, arn),
 FOREIGN KEY (partition, account_id, region, policy_name)
 REFERENCES xray_resource_policies(partition, account_id, region, name) ON DELETE CASCADE
);
