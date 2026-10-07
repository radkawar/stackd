ALTER TABLE cognitoidp_pools ADD COLUMN software_token_mfa_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cognitoidp_users ADD COLUMN software_token_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_users ADD COLUMN software_token_pending_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_users ADD COLUMN software_token_pending_expires TIMESTAMP;
ALTER TABLE cognitoidp_users ADD COLUMN software_token_last_counter INTEGER NOT NULL DEFAULT -1;
ALTER TABLE cognitoidp_users ADD COLUMN software_token_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cognitoidp_users ADD COLUMN software_token_preferred BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cognitoidp_users ADD COLUMN software_token_device_name TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_challenges ADD COLUMN software_token_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_challenges ADD COLUMN software_token_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE cognitoidp_sessions ADD COLUMN oauth_scope TEXT NOT NULL DEFAULT '';
ALTER TABLE cognitoidp_sessions ADD COLUMN oauth_nonce TEXT NOT NULL DEFAULT '';

CREATE TABLE cognitoidp_oauth (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 token TEXT NOT NULL,
 client_id TEXT NOT NULL,
 provider_name TEXT NOT NULL,
 redirect_uri TEXT NOT NULL,
 client_state TEXT NOT NULL,
 nonce TEXT NOT NULL,
 pkce_challenge TEXT NOT NULL,
 upstream_nonce TEXT NOT NULL,
 upstream_verifier TEXT NOT NULL,
 scope TEXT NOT NULL,
 username TEXT NOT NULL,
 phase TEXT NOT NULL,
 expires TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, token),
 FOREIGN KEY (partition, account_id, region, pool_id, client_id) REFERENCES cognitoidp_clients (partition, account_id, region, pool_id, client_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, pool_id, provider_name) REFERENCES cognitoidp_identity_providers (partition, account_id, region, pool_id, provider_name) ON DELETE CASCADE
);
