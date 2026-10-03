CREATE TABLE apigateway_usage_plans (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT,
 throttle_burst INTEGER,
 throttle_rate REAL,
 quota_limit INTEGER,
 quota_offset INTEGER,
 quota_period TEXT,
 PRIMARY KEY (partition, account_id, region, plan_id)
);

CREATE TABLE apigateway_usage_plan_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, plan_id, key),
 FOREIGN KEY (partition, account_id, region, plan_id) REFERENCES apigateway_usage_plans (partition, account_id, region, plan_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_usage_plan_stages (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 api_id TEXT NOT NULL,
 stage_name TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 throttle_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, plan_id, api_id, stage_name),
 FOREIGN KEY (partition, account_id, region, plan_id) REFERENCES apigateway_usage_plans (partition, account_id, region, plan_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, api_id, stage_name) REFERENCES apigateway_stages (partition, account_id, region, api_id, name) ON DELETE CASCADE
);

CREATE TABLE apigateway_usage_plan_method_throttles (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 api_id TEXT NOT NULL,
 stage_name TEXT NOT NULL,
 method_path TEXT NOT NULL,
 burst INTEGER NOT NULL,
 rate REAL NOT NULL,
 PRIMARY KEY (partition, account_id, region, plan_id, api_id, stage_name, method_path),
 FOREIGN KEY (partition, account_id, region, plan_id, api_id, stage_name) REFERENCES apigateway_usage_plan_stages (partition, account_id, region, plan_id, api_id, stage_name) ON DELETE CASCADE
);

CREATE TABLE apigateway_usage_plan_memberships (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 client_key_id TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, plan_id, client_key_id),
 FOREIGN KEY (partition, account_id, region, plan_id) REFERENCES apigateway_usage_plans (partition, account_id, region, plan_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, client_key_id) REFERENCES apigateway_client_keys (partition, account_id, region, client_key_id) ON DELETE CASCADE
);
CREATE INDEX apigateway_usage_plan_memberships_by_key ON apigateway_usage_plan_memberships (partition, account_id, region, client_key_id, plan_id);

-- Usage belongs to the key and plan, not a transient membership. Detaching and
-- reattaching an existing key must not silently discard its admitted traffic.
CREATE TABLE apigateway_usage_days (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 plan_id TEXT NOT NULL,
 client_key_id TEXT NOT NULL,
 day TIMESTAMP NOT NULL,
 used INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, plan_id, client_key_id, day),
 FOREIGN KEY (partition, account_id, region, plan_id) REFERENCES apigateway_usage_plans (partition, account_id, region, plan_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, client_key_id) REFERENCES apigateway_client_keys (partition, account_id, region, client_key_id) ON DELETE CASCADE
);
