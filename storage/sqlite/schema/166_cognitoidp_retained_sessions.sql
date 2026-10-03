-- Retain revoked session families after user deletion, while client deletion still cascades.
ALTER TABLE cognitoidp_sessions RENAME TO cognitoidp_sessions_user_owned;

CREATE TABLE cognitoidp_sessions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 username TEXT NOT NULL,
 origin_id TEXT NOT NULL,
 auth_time TIMESTAMP NOT NULL,
 refresh_expires TIMESTAMP NOT NULL,
 refresh_digest BLOB,
 revoked BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, session_id),
 FOREIGN KEY (partition, account_id, region, pool_id, client_id) REFERENCES cognitoidp_clients(partition, account_id, region, pool_id, client_id) ON DELETE CASCADE
);

INSERT INTO cognitoidp_sessions(partition, account_id, region, pool_id, session_id, client_id, username, origin_id, auth_time, refresh_expires, refresh_digest, revoked)
 SELECT partition, account_id, region, pool_id, session_id, client_id, username, origin_id, auth_time, refresh_expires, refresh_digest, revoked
 FROM cognitoidp_sessions_user_owned;
DROP TABLE cognitoidp_sessions_user_owned;

CREATE INDEX cognitoidp_sessions_user ON cognitoidp_sessions(partition, account_id, region, pool_id, username);
CREATE UNIQUE INDEX cognitoidp_sessions_refresh ON cognitoidp_sessions(partition, account_id, region, pool_id, client_id, refresh_digest);
CREATE INDEX cognitoidp_sessions_expiry ON cognitoidp_sessions(refresh_expires);
