-- Refresh families keep only their current and previous accepted tokens; every
-- issued digest retains family ownership for reuse detection and revocation.
ALTER TABLE cognitoidp_sessions ADD COLUMN previous_refresh_digest BLOB;
ALTER TABLE cognitoidp_sessions ADD COLUMN refresh_grace_expires TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE cognitoidp_sessions ADD COLUMN refresh_origin_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_sessions ADD COLUMN globally_revoked BOOLEAN NOT NULL DEFAULT false;
UPDATE cognitoidp_sessions SET refresh_origin_id = origin_id, globally_revoked = revoked;

CREATE TABLE cognitoidp_refresh_tokens (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 refresh_digest BLOB NOT NULL,
 session_id TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, client_id, refresh_digest),
 FOREIGN KEY (partition, account_id, region, pool_id, session_id) REFERENCES cognitoidp_sessions(partition, account_id, region, pool_id, session_id) ON DELETE CASCADE
);

CREATE INDEX cognitoidp_refresh_tokens_session ON cognitoidp_refresh_tokens(partition, account_id, region, pool_id, session_id);

-- Existing family attribution, expiry and revocation are unchanged. Families
-- without an issued refresh digest have no token identity to retain.
INSERT INTO cognitoidp_refresh_tokens(partition, account_id, region, pool_id, client_id, refresh_digest, session_id)
 SELECT partition, account_id, region, pool_id, client_id, refresh_digest, session_id
 FROM cognitoidp_sessions WHERE refresh_digest IS NOT NULL;

DROP INDEX cognitoidp_sessions_refresh;
