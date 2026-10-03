CREATE TABLE cognitoidp_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 group_name TEXT NOT NULL,
 creation_date TIMESTAMP,
 description TEXT,
 last_modified_date TIMESTAMP,
 precedence INTEGER,
 role_arn TEXT,
 PRIMARY KEY (partition, account_id, region, pool_id, group_name),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

CREATE TABLE cognitoidp_group_users (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 group_name TEXT NOT NULL,
 username TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, group_name, username),
 FOREIGN KEY (partition, account_id, region, pool_id, group_name) REFERENCES cognitoidp_groups(partition, account_id, region, pool_id, group_name) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, pool_id, username) REFERENCES cognitoidp_users(partition, account_id, region, pool_id, username) ON DELETE CASCADE
);

CREATE INDEX cognitoidp_group_users_user ON cognitoidp_group_users(partition, account_id, region, pool_id, username, group_name);
