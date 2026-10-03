CREATE TABLE ec2_key_pairs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 key_pair_id TEXT,
 key_name TEXT,
 key_fingerprint TEXT,
 key_type TEXT,
 public_key TEXT,
 create_time DATETIME,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id),
 UNIQUE (partition, account_id, region, key_name)
);

CREATE TABLE ec2_key_pair_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_key_pairs (partition, account_id, region, resource_id) ON DELETE CASCADE
);
