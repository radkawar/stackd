CREATE TABLE mq_brokers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 instance_type TEXT NOT NULL,
 state TEXT NOT NULL,
 creator_request_id TEXT NOT NULL,
 username TEXT NOT NULL,
 password TEXT NOT NULL,
 operation TEXT NOT NULL,
 failure TEXT NOT NULL,
 version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,
 due TIMESTAMP NOT NULL,
 endpoint_address TEXT NOT NULL,
 endpoint_console_url TEXT NOT NULL,
 endpoint_native_id TEXT NOT NULL,
 endpoint_ca_pem BLOB NOT NULL,
 PRIMARY KEY(partition,account_id,region,id),
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE mq_broker_tags (
 arn TEXT NOT NULL REFERENCES mq_brokers(arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
