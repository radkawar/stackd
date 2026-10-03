-- Cognito owns typed pool configuration and authentication state.
-- JSON columns each contain one generated nested configuration, never a resource.

CREATE TABLE cognitoidp_pools (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 account_recovery_setting BLOB NOT NULL,
 admin_create_user_config BLOB NOT NULL,
 alias_attributes BLOB NOT NULL,
 arn TEXT,
 auto_verified_attributes BLOB NOT NULL,
 creation_date TIMESTAMP,
 custom_domain TEXT,
 deletion_protection TEXT,
 device_configuration BLOB NOT NULL,
 domain TEXT,
 email_configuration BLOB NOT NULL,
 email_configuration_failure TEXT,
 email_verification_message TEXT,
 email_verification_subject TEXT,
 estimated_number_of_users INTEGER,
 issuer_configuration BLOB NOT NULL,
 key_configuration BLOB NOT NULL,
 lambda_config BLOB NOT NULL,
 last_modified_date TIMESTAMP,
 mfa_configuration TEXT,
 name TEXT,
 policies BLOB NOT NULL,
 schema_attributes BLOB NOT NULL,
 sms_authentication_message TEXT,
 sms_configuration BLOB NOT NULL,
 sms_configuration_failure TEXT,
 sms_verification_message TEXT,
 status TEXT,
 user_attribute_update_settings BLOB NOT NULL,
 user_pool_add_ons BLOB NOT NULL,
 user_pool_tags BLOB NOT NULL,
 user_pool_tier TEXT,
 username_attributes BLOB NOT NULL,
 username_configuration BLOB NOT NULL,
 verification_message_template BLOB NOT NULL,
 issuer_url TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id)
);

CREATE TABLE cognitoidp_clients (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 access_token_validity INTEGER,
 allowed_o_auth_flows BLOB NOT NULL,
 allowed_o_auth_flows_user_pool_client BOOLEAN,
 allowed_o_auth_scopes BLOB NOT NULL,
 analytics_configuration BLOB NOT NULL,
 auth_session_validity INTEGER,
 callback_urls BLOB NOT NULL,
 client_name TEXT,
 client_secret TEXT,
 creation_date TIMESTAMP,
 default_redirect_uri TEXT,
 enable_propagate_additional_user_context_data BOOLEAN,
 enable_token_revocation BOOLEAN,
 explicit_auth_flows BLOB NOT NULL,
 id_token_validity INTEGER,
 last_modified_date TIMESTAMP,
 logout_urls BLOB NOT NULL,
 prevent_user_existence_errors TEXT,
 read_attributes BLOB NOT NULL,
 refresh_token_rotation BLOB NOT NULL,
 refresh_token_validity INTEGER,
 supported_identity_providers BLOB NOT NULL,
 token_validity_units BLOB NOT NULL,
 write_attributes BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, pool_id, client_id),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

CREATE TABLE cognitoidp_users (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 username TEXT NOT NULL,
 enabled BOOLEAN,
 mfa_options BLOB NOT NULL,
 user_create_date TIMESTAMP,
 user_last_modified_date TIMESTAMP,
 user_status TEXT,
 attributes_present BOOLEAN NOT NULL,
 password_salt BLOB,
 password_verifier BLOB,
 password_expires TIMESTAMP,
 PRIMARY KEY (partition, account_id, region, pool_id, username),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

CREATE TABLE cognitoidp_user_attributes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 username TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, pool_id, username, position),
 FOREIGN KEY (partition, account_id, region, pool_id, username) REFERENCES cognitoidp_users(partition, account_id, region, pool_id, username) ON DELETE CASCADE
);

CREATE TABLE cognitoidp_signing_keys (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 access_key_id TEXT NOT NULL,
 access_key_der BLOB,
 id_key_id TEXT NOT NULL,
 id_key_der BLOB,
 PRIMARY KEY (partition, account_id, region, pool_id),
 FOREIGN KEY (partition, account_id, region, pool_id) REFERENCES cognitoidp_pools(partition, account_id, region, pool_id) ON DELETE CASCADE
);

CREATE TABLE cognitoidp_challenges (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 token TEXT NOT NULL,
 client_id TEXT NOT NULL,
 username TEXT NOT NULL,
 kind TEXT NOT NULL,
 expires TIMESTAMP NOT NULL,
 srp_private BLOB,
 PRIMARY KEY (partition, account_id, region, pool_id, token),
 FOREIGN KEY (partition, account_id, region, pool_id, client_id) REFERENCES cognitoidp_clients(partition, account_id, region, pool_id, client_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, pool_id, username) REFERENCES cognitoidp_users(partition, account_id, region, pool_id, username) ON DELETE CASCADE
);

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
 FOREIGN KEY (partition, account_id, region, pool_id, client_id) REFERENCES cognitoidp_clients(partition, account_id, region, pool_id, client_id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, pool_id, username) REFERENCES cognitoidp_users(partition, account_id, region, pool_id, username) ON DELETE CASCADE
);

CREATE UNIQUE INDEX cognitoidp_pools_public_id ON cognitoidp_pools(partition, region, pool_id);
CREATE UNIQUE INDEX cognitoidp_clients_public_id ON cognitoidp_clients(partition, region, client_id);
CREATE INDEX cognitoidp_user_attribute_lookup ON cognitoidp_user_attributes(partition, account_id, region, pool_id, name, value, username);
CREATE INDEX cognitoidp_challenges_client ON cognitoidp_challenges(partition, account_id, region, pool_id, client_id);
CREATE INDEX cognitoidp_challenges_user ON cognitoidp_challenges(partition, account_id, region, pool_id, username);
CREATE INDEX cognitoidp_challenges_expiry ON cognitoidp_challenges(expires);
CREATE INDEX cognitoidp_sessions_user ON cognitoidp_sessions(partition, account_id, region, pool_id, username);
CREATE UNIQUE INDEX cognitoidp_sessions_refresh ON cognitoidp_sessions(partition, account_id, region, pool_id, client_id, refresh_digest);
CREATE INDEX cognitoidp_sessions_expiry ON cognitoidp_sessions(refresh_expires);
