-- Usage-plan keys are account/region resources, not children of a REST API.
CREATE TABLE apigateway_client_keys (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 client_key_id TEXT NOT NULL,
 name TEXT,
 description TEXT,
 customer_id TEXT,
 value TEXT NOT NULL,
 enabled BOOLEAN NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, client_key_id),
 UNIQUE (partition, account_id, region, value)
);

CREATE TABLE apigateway_client_key_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 client_key_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, client_key_id, key),
 FOREIGN KEY (partition, account_id, region, client_key_id) REFERENCES apigateway_client_keys (partition, account_id, region, client_key_id) ON DELETE CASCADE
);

CREATE TABLE apigateway_client_key_stages (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 client_key_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 api_id TEXT NOT NULL,
 stage_name TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, client_key_id, ordinal),
 FOREIGN KEY (partition, account_id, region, client_key_id) REFERENCES apigateway_client_keys (partition, account_id, region, client_key_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, api_id, stage_name) REFERENCES apigateway_stages (partition, account_id, region, api_id, name) ON DELETE CASCADE
);
