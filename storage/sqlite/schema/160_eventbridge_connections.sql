-- Public Connection metadata only. Credential values and OAuth tokens belong to
-- the Secrets Manager owner; secret HTTP parameter rows retain only their keys.
CREATE TABLE eventbridge_connections (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL,
 authorization_type TEXT NOT NULL,
 state TEXT NOT NULL,
 state_reason TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 kms_key_identifier TEXT NOT NULL,
 username TEXT NOT NULL,
 api_key_name TEXT NOT NULL,
 client_id TEXT NOT NULL,
 authorization_endpoint TEXT NOT NULL,
 oauth_method TEXT NOT NULL,
 has_auth BOOLEAN NOT NULL,
 has_invocation BOOLEAN NOT NULL,
 has_oauth_http BOOLEAN NOT NULL,
 created TIMESTAMP NOT NULL,
 modified TIMESTAMP NOT NULL,
 last_authorized TIMESTAMP,
 due_seconds INTEGER,
 due_nanos INTEGER NOT NULL,
 version BLOB NOT NULL CHECK(length(version)=8),
 PRIMARY KEY(partition,account,region,name)
);
CREATE INDEX eventbridge_connections_due ON eventbridge_connections(due_seconds,due_nanos,id) WHERE due_seconds IS NOT NULL;
CREATE TABLE eventbridge_connection_parameters (
 connection_id TEXT NOT NULL REFERENCES eventbridge_connections(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 target TEXT NOT NULL CHECK(target IN ('invocation','oauth')),
 location TEXT NOT NULL CHECK(location IN ('header','query','body')),
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 secret BOOLEAN NOT NULL CHECK(secret IN (0,1)),
 CHECK(secret=0 OR value=''),
 PRIMARY KEY(connection_id,ordinal)
);
