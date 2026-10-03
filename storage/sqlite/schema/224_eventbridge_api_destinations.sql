CREATE TABLE eventbridge_api_destinations (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL,
 connection_arn TEXT NOT NULL,
 endpoint TEXT NOT NULL,
 method TEXT NOT NULL,
 rate INTEGER NOT NULL CHECK(rate >= 1),
 created TIMESTAMP NOT NULL,
 modified TIMESTAMP NOT NULL,
 rate_window TIMESTAMP,
 rate_count INTEGER NOT NULL CHECK(rate_count >= 0),
 version BLOB NOT NULL CHECK(length(version)=8),
 PRIMARY KEY(partition,account,region,name)
);

-- HTTP parameter components use the existing typed target-parameter convention.
-- Admitted deliveries retain their own parameters independently of target changes.
ALTER TABLE eventbridge_targets ADD COLUMN http_present BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE eventbridge_targets ADD COLUMN http_headers BLOB NOT NULL DEFAULT X'6e756c6c';
ALTER TABLE eventbridge_targets ADD COLUMN http_paths BLOB NOT NULL DEFAULT X'6e756c6c';
ALTER TABLE eventbridge_targets ADD COLUMN http_query BLOB NOT NULL DEFAULT X'6e756c6c';
ALTER TABLE eventbridge_deliveries ADD COLUMN http_present BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE eventbridge_deliveries ADD COLUMN http_headers BLOB NOT NULL DEFAULT X'6e756c6c';
ALTER TABLE eventbridge_deliveries ADD COLUMN http_paths BLOB NOT NULL DEFAULT X'6e756c6c';
ALTER TABLE eventbridge_deliveries ADD COLUMN http_query BLOB NOT NULL DEFAULT X'6e756c6c';

-- Pipes invokes the same destination owner and retains its modeled parameters.
ALTER TABLE pipes_pipes ADD COLUMN target_http_present BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE pipes_pipes ADD COLUMN target_http_headers TEXT NOT NULL DEFAULT 'null';
ALTER TABLE pipes_pipes ADD COLUMN target_http_paths TEXT NOT NULL DEFAULT 'null';
ALTER TABLE pipes_pipes ADD COLUMN target_http_query TEXT NOT NULL DEFAULT 'null';
