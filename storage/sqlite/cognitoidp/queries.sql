-- name: GetPool :one
SELECT * FROM cognitoidp_pools WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ?;

-- name: PutPool :exec
INSERT INTO cognitoidp_pools (
 partition, account_id, region, pool_id, account_recovery_setting, admin_create_user_config, alias_attributes, arn, auto_verified_attributes, creation_date, custom_domain, deletion_protection, device_configuration, domain, email_configuration, email_configuration_failure, email_verification_message, email_verification_subject, estimated_number_of_users, issuer_configuration, key_configuration, lambda_config, last_modified_date, mfa_configuration, name, policies, schema_attributes, sms_authentication_message, sms_configuration, sms_configuration_failure, sms_verification_message, status, user_attribute_update_settings, user_pool_add_ons, user_pool_tags, user_pool_tier, username_attributes, username_configuration, verification_message_template, issuer_url, software_token_mfa_enabled
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id) DO UPDATE SET
 account_recovery_setting = excluded.account_recovery_setting,
 admin_create_user_config = excluded.admin_create_user_config,
 alias_attributes = excluded.alias_attributes,
 arn = excluded.arn,
 auto_verified_attributes = excluded.auto_verified_attributes,
 creation_date = excluded.creation_date,
 custom_domain = excluded.custom_domain,
 deletion_protection = excluded.deletion_protection,
 device_configuration = excluded.device_configuration,
 domain = excluded.domain,
 email_configuration = excluded.email_configuration,
 email_configuration_failure = excluded.email_configuration_failure,
 email_verification_message = excluded.email_verification_message,
 email_verification_subject = excluded.email_verification_subject,
 estimated_number_of_users = excluded.estimated_number_of_users,
 issuer_configuration = excluded.issuer_configuration,
 key_configuration = excluded.key_configuration,
 lambda_config = excluded.lambda_config,
 last_modified_date = excluded.last_modified_date,
 mfa_configuration = excluded.mfa_configuration,
 name = excluded.name,
 policies = excluded.policies,
 schema_attributes = excluded.schema_attributes,
 sms_authentication_message = excluded.sms_authentication_message,
 sms_configuration = excluded.sms_configuration,
 sms_configuration_failure = excluded.sms_configuration_failure,
 sms_verification_message = excluded.sms_verification_message,
 status = excluded.status,
 user_attribute_update_settings = excluded.user_attribute_update_settings,
 user_pool_add_ons = excluded.user_pool_add_ons,
 user_pool_tags = excluded.user_pool_tags,
 user_pool_tier = excluded.user_pool_tier,
 username_attributes = excluded.username_attributes,
 username_configuration = excluded.username_configuration,
 verification_message_template = excluded.verification_message_template,
 issuer_url = excluded.issuer_url,
 software_token_mfa_enabled = excluded.software_token_mfa_enabled;

-- name: DeletePool :exec
DELETE FROM cognitoidp_pools WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ?;

-- name: GetClient :one
SELECT * FROM cognitoidp_clients WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND client_id = ?;

-- name: PutClient :exec
INSERT INTO cognitoidp_clients (
 partition, account_id, region, pool_id, client_id, access_token_validity, allowed_o_auth_flows, allowed_o_auth_flows_user_pool_client, allowed_o_auth_scopes, analytics_configuration, auth_session_validity, callback_urls, client_name, client_secret, creation_date, default_redirect_uri, enable_propagate_additional_user_context_data, enable_token_revocation, explicit_auth_flows, id_token_validity, last_modified_date, logout_urls, prevent_user_existence_errors, read_attributes, refresh_token_rotation, refresh_token_validity, supported_identity_providers, token_validity_units, write_attributes
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, client_id) DO UPDATE SET
 access_token_validity = excluded.access_token_validity,
 allowed_o_auth_flows = excluded.allowed_o_auth_flows,
 allowed_o_auth_flows_user_pool_client = excluded.allowed_o_auth_flows_user_pool_client,
 allowed_o_auth_scopes = excluded.allowed_o_auth_scopes,
 analytics_configuration = excluded.analytics_configuration,
 auth_session_validity = excluded.auth_session_validity,
 callback_urls = excluded.callback_urls,
 client_name = excluded.client_name,
 client_secret = excluded.client_secret,
 creation_date = excluded.creation_date,
 default_redirect_uri = excluded.default_redirect_uri,
 enable_propagate_additional_user_context_data = excluded.enable_propagate_additional_user_context_data,
 enable_token_revocation = excluded.enable_token_revocation,
 explicit_auth_flows = excluded.explicit_auth_flows,
 id_token_validity = excluded.id_token_validity,
 last_modified_date = excluded.last_modified_date,
 logout_urls = excluded.logout_urls,
 prevent_user_existence_errors = excluded.prevent_user_existence_errors,
 read_attributes = excluded.read_attributes,
 refresh_token_rotation = excluded.refresh_token_rotation,
 refresh_token_validity = excluded.refresh_token_validity,
 supported_identity_providers = excluded.supported_identity_providers,
 token_validity_units = excluded.token_validity_units,
 write_attributes = excluded.write_attributes;

-- name: DeleteClient :exec
DELETE FROM cognitoidp_clients WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND client_id = ?;

-- name: GetUser :one
SELECT * FROM cognitoidp_users WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ?;

-- name: PutUser :exec
INSERT INTO cognitoidp_users (
 partition, account_id, region, pool_id, username, enabled, mfa_options, user_create_date, user_last_modified_date, user_status, attributes_present, password_salt, password_verifier, password_expires, software_token_secret, software_token_pending_secret, software_token_pending_expires, software_token_last_counter, software_token_enabled, software_token_preferred, software_token_device_name
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, username) DO UPDATE SET
 enabled = excluded.enabled,
 mfa_options = excluded.mfa_options,
 user_create_date = excluded.user_create_date,
 user_last_modified_date = excluded.user_last_modified_date,
 user_status = excluded.user_status,
 attributes_present = excluded.attributes_present,
 password_salt = excluded.password_salt,
 password_verifier = excluded.password_verifier,
 password_expires = excluded.password_expires,
 software_token_secret = excluded.software_token_secret,
 software_token_pending_secret = excluded.software_token_pending_secret,
 software_token_pending_expires = excluded.software_token_pending_expires,
 software_token_last_counter = excluded.software_token_last_counter,
 software_token_enabled = excluded.software_token_enabled,
 software_token_preferred = excluded.software_token_preferred,
 software_token_device_name = excluded.software_token_device_name;

-- name: DeleteUser :exec
DELETE FROM cognitoidp_users WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ?;

-- name: GetSigningKeys :one
SELECT * FROM cognitoidp_signing_keys WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ?;

-- name: PutSigningKeys :exec
INSERT INTO cognitoidp_signing_keys (
 partition, account_id, region, pool_id, access_key_id, access_key_der, id_key_id, id_key_der
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id) DO UPDATE SET
 access_key_id = excluded.access_key_id,
 access_key_der = excluded.access_key_der,
 id_key_id = excluded.id_key_id,
 id_key_der = excluded.id_key_der;

-- name: GetChallenge :one
SELECT * FROM cognitoidp_challenges WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND token = ?;

-- name: PutChallenge :exec
INSERT INTO cognitoidp_challenges (
 partition, account_id, region, pool_id, token, client_id, username, kind, expires, srp_private, software_token_secret, software_token_verified
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, token) DO UPDATE SET
 client_id = excluded.client_id,
 username = excluded.username,
 kind = excluded.kind,
 expires = excluded.expires,
 srp_private = excluded.srp_private,
 software_token_secret = excluded.software_token_secret,
 software_token_verified = excluded.software_token_verified;

-- name: DeleteChallenge :exec
DELETE FROM cognitoidp_challenges WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND token = ?;

-- name: GetSession :one
SELECT * FROM cognitoidp_sessions WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND session_id = ?;

-- name: PutSession :exec
INSERT INTO cognitoidp_sessions (
 partition, account_id, region, pool_id, session_id, client_id, username, origin_id, auth_time, refresh_expires, refresh_digest, revoked, previous_refresh_digest, refresh_grace_expires, refresh_origin_id, globally_revoked, oauth_scope, oauth_nonce
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, session_id) DO UPDATE SET
 client_id = excluded.client_id,
 username = excluded.username,
 origin_id = excluded.origin_id,
 auth_time = excluded.auth_time,
 refresh_expires = excluded.refresh_expires,
 refresh_digest = excluded.refresh_digest,
 revoked = excluded.revoked,
 previous_refresh_digest = excluded.previous_refresh_digest,
 refresh_grace_expires = excluded.refresh_grace_expires,
 refresh_origin_id = excluded.refresh_origin_id,
 globally_revoked = excluded.globally_revoked,
 oauth_scope = excluded.oauth_scope,
 oauth_nonce = excluded.oauth_nonce;

-- name: PutRefreshToken :exec
INSERT INTO cognitoidp_refresh_tokens (
 partition, account_id, region, pool_id, client_id, refresh_digest, session_id
) VALUES (
 ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, client_id, refresh_digest) DO NOTHING;


-- name: ListPools :many
SELECT * FROM cognitoidp_pools WHERE partition = ? AND account_id = ? AND region = ? ORDER BY pool_id;

-- name: ListClients :many
SELECT * FROM cognitoidp_clients WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? ORDER BY client_id;

-- name: ListUsers :many
SELECT * FROM cognitoidp_users WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? ORDER BY username;

-- name: GetPoolByID :one
SELECT * FROM cognitoidp_pools WHERE partition = ? AND region = ? AND pool_id = ?;

-- name: GetClientByID :one
SELECT * FROM cognitoidp_clients WHERE partition = ? AND region = ? AND client_id = ?;

-- name: ListUsersByAttribute :many
SELECT DISTINCT u.* FROM cognitoidp_users u
JOIN cognitoidp_user_attributes a ON a.partition = u.partition AND a.account_id = u.account_id
 AND a.region = u.region AND a.pool_id = u.pool_id AND a.username = u.username
WHERE a.partition = ? AND a.account_id = ? AND a.region = ? AND a.pool_id = ?
 AND a.name = ? AND a.value = ? ORDER BY u.username;

-- name: ListUserAttributes :many
SELECT * FROM cognitoidp_user_attributes WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ? ORDER BY position;

-- name: PutUserAttribute :exec
INSERT INTO cognitoidp_user_attributes (
 partition, account_id, region, pool_id, username, position, name, value
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, username, position) DO UPDATE SET
 name = excluded.name,
 value = excluded.value;

-- name: DeleteUserAttributes :exec
DELETE FROM cognitoidp_user_attributes WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ?;

-- name: GetSessionByRefresh :one
SELECT s.* FROM cognitoidp_sessions s
JOIN cognitoidp_refresh_tokens t ON t.partition = s.partition AND t.account_id = s.account_id
 AND t.region = s.region AND t.pool_id = s.pool_id AND t.client_id = s.client_id AND t.session_id = s.session_id
WHERE t.partition = ? AND t.account_id = ? AND t.region = ? AND t.pool_id = ?
 AND t.client_id = ? AND t.refresh_digest = ?;

-- name: RevokeUserSessions :exec
UPDATE cognitoidp_sessions SET revoked = true, globally_revoked = true WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ?;

-- name: GetGroup :one
SELECT * FROM cognitoidp_groups WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND group_name = ?;

-- name: ListGroups :many
SELECT * FROM cognitoidp_groups WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? ORDER BY group_name;

-- name: ListGroupsForUser :many
SELECT g.* FROM cognitoidp_groups g
JOIN cognitoidp_group_users m ON m.partition = g.partition AND m.account_id = g.account_id
 AND m.region = g.region AND m.pool_id = g.pool_id AND m.group_name = g.group_name
WHERE m.partition = ? AND m.account_id = ? AND m.region = ? AND m.pool_id = ?
 AND m.username = ? ORDER BY g.group_name;

-- name: ListUsersInGroup :many
SELECT u.* FROM cognitoidp_users u
JOIN cognitoidp_group_users m ON m.partition = u.partition AND m.account_id = u.account_id
 AND m.region = u.region AND m.pool_id = u.pool_id AND m.username = u.username
WHERE m.partition = ? AND m.account_id = ? AND m.region = ? AND m.pool_id = ?
 AND m.group_name = ? ORDER BY u.username;

-- name: PutGroup :exec
INSERT INTO cognitoidp_groups (
 partition, account_id, region, pool_id, group_name, creation_date, description, last_modified_date, precedence, role_arn
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, group_name) DO UPDATE SET
 creation_date = excluded.creation_date,
 description = excluded.description,
 last_modified_date = excluded.last_modified_date,
 precedence = excluded.precedence,
 role_arn = excluded.role_arn;

-- name: DeleteGroup :exec
DELETE FROM cognitoidp_groups WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND group_name = ?;

-- name: AddGroupUser :exec
INSERT INTO cognitoidp_group_users (
 partition, account_id, region, pool_id, group_name, username
) VALUES (
 ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, group_name, username) DO NOTHING;

-- name: RemoveGroupUser :exec
DELETE FROM cognitoidp_group_users WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND group_name = ? AND username = ?;

-- name: ListPoolsForAccount :many
SELECT * FROM cognitoidp_pools WHERE partition = ? AND account_id = ? ORDER BY region,pool_id;

-- name: GetEmailCode :one
SELECT * FROM cognitoidp_email_codes WHERE partition=? AND account_id=? AND region=? AND pool_id=? AND username=? AND kind=?;

-- name: PutEmailCode :exec
INSERT INTO cognitoidp_email_codes(partition,account_id,region,pool_id,username,kind,expires,digest) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,pool_id,username,kind) DO UPDATE SET expires=excluded.expires,digest=excluded.digest;

-- name: DeleteEmailCode :exec
DELETE FROM cognitoidp_email_codes WHERE partition=? AND account_id=? AND region=? AND pool_id=? AND username=? AND kind=?;

-- name: ListClientsByIDInPartition :many
SELECT * FROM cognitoidp_clients WHERE partition = ? AND client_id = ? ORDER BY region, account_id;

-- name: GetPoolByDomain :one
SELECT * FROM cognitoidp_pools WHERE partition = ? AND region = ? AND domain = ?;

-- name: GetResourceOwner :one
SELECT * FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = ? AND name = ?;

-- name: GetPoolResourceOwner :one
SELECT * FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND kind = 'pool' AND stack_id = ? AND logical_id = ? AND token = ?;

-- name: PutResourceOwner :exec
INSERT INTO cognitoidp_resource_owners (
 partition, account_id, region, pool_id, kind, name, physical_id, member_user, member_group, stack_id, logical_id, token
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, kind, name) DO UPDATE SET
 physical_id = excluded.physical_id,
 member_user = excluded.member_user,
 member_group = excluded.member_group,
 stack_id = excluded.stack_id,
 logical_id = excluded.logical_id,
 token = excluded.token;

-- name: DeleteResourceOwner :exec
DELETE FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = ? AND name = ?;

-- name: DeleteResourceOwnersByPhysicalID :exec
DELETE FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = ? AND physical_id = ?;

-- name: DeleteMembershipOwnersByUser :exec
DELETE FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = 'membership' AND member_user = ?;

-- name: DeleteMembershipOwnersByGroup :exec
DELETE FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = 'membership' AND member_group = ?;

-- name: DeleteMembershipOwner :exec
DELETE FROM cognitoidp_resource_owners WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND kind = 'membership' AND member_user = ? AND member_group = ?;

-- name: GetIdentityProvider :one
SELECT * FROM cognitoidp_identity_providers WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND provider_name = ?;

-- name: ListIdentityProviders :many
SELECT * FROM cognitoidp_identity_providers WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? ORDER BY provider_name;

-- name: PutIdentityProvider :exec
INSERT INTO cognitoidp_identity_providers (
 partition, account_id, region, pool_id, provider_name, provider_type, provider_details, attribute_mapping, idp_identifiers, creation_date, last_modified_date
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, pool_id, provider_name) DO UPDATE SET
 provider_type = excluded.provider_type,
 provider_details = excluded.provider_details,
 attribute_mapping = excluded.attribute_mapping,
 idp_identifiers = excluded.idp_identifiers,
 creation_date = excluded.creation_date,
 last_modified_date = excluded.last_modified_date;

-- name: DeleteIdentityProvider :exec
DELETE FROM cognitoidp_identity_providers WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND provider_name = ?;

-- name: DeleteOAuthForUser :exec
DELETE FROM cognitoidp_oauth WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND username = ?;
