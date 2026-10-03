-- name: EnsureScope :exec
INSERT INTO iam_scopes (partition, account) VALUES (?, ?) ON CONFLICT DO NOTHING;

-- name: Scopes :many
SELECT * FROM iam_scopes WHERE partition = ? ORDER BY account;

-- name: GetUser :one
SELECT * FROM iam_user WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertUser :exec
INSERT INTO iam_user (partition, account, resource_key, path, user_name, user_id, arn, create_date, password_last_used)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteUser :execrows
DELETE FROM iam_user WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListUserKeys :many
SELECT partition, account, resource_key FROM iam_user WHERE partition = ? AND account = ? ORDER BY user_name;

-- name: GetUserPermissionsBoundary :one
SELECT * FROM iam_user_permissions_boundary WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertUserPermissionsBoundary :exec
INSERT INTO iam_user_permissions_boundary (partition, account, resource_key, permissions_boundary_type, permissions_boundary_arn)
VALUES (?, ?, ?, ?, ?);

-- name: ListUserTags :many
SELECT * FROM iam_user_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertUserTags :exec
INSERT INTO iam_user_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListUserInline :many
SELECT * FROM iam_user_inline WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertUserInline :exec
INSERT INTO iam_user_inline (partition, account, resource_key, entry_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: ListUserAttached :many
SELECT * FROM iam_user_attached WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertUserAttached :exec
INSERT INTO iam_user_attached (partition, account, resource_key, entry_1)
VALUES (?, ?, ?, ?);

-- name: GetGroup :one
SELECT * FROM iam_group WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertGroup :exec
INSERT INTO iam_group (partition, account, resource_key, path, group_name, group_id, arn, create_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteGroup :execrows
DELETE FROM iam_group WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListGroupKeys :many
SELECT partition, account, resource_key FROM iam_group WHERE partition = ? AND account = ? ORDER BY group_name;

-- name: ListGroupInline :many
SELECT * FROM iam_group_inline WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertGroupInline :exec
INSERT INTO iam_group_inline (partition, account, resource_key, entry_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: ListGroupAttached :many
SELECT * FROM iam_group_attached WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertGroupAttached :exec
INSERT INTO iam_group_attached (partition, account, resource_key, entry_1)
VALUES (?, ?, ?, ?);

-- name: ListGroupMembers :many
SELECT * FROM iam_group_members WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertGroupMembers :exec
INSERT INTO iam_group_members (partition, account, resource_key, entry_1)
VALUES (?, ?, ?, ?);

-- name: GetRole :one
SELECT * FROM iam_role WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertRole :exec
INSERT INTO iam_role (partition, account, resource_key, path, role_name, role_id, arn, assume_role_policy_document, description, service_linked_service, last_used_region, create_date, last_used_date, max_session_duration, identity_center_instance_arn, identity_center_permission_set_arn)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteRole :execrows
DELETE FROM iam_role WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListRoleKeys :many
SELECT partition, account, resource_key FROM iam_role WHERE partition = ? AND account = ? ORDER BY role_name;

-- name: GetRolePermissionsBoundary :one
SELECT * FROM iam_role_permissions_boundary WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertRolePermissionsBoundary :exec
INSERT INTO iam_role_permissions_boundary (partition, account, resource_key, permissions_boundary_type, permissions_boundary_arn)
VALUES (?, ?, ?, ?, ?);

-- name: ListRoleTags :many
SELECT * FROM iam_role_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertRoleTags :exec
INSERT INTO iam_role_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListRoleTrustPrincipalIDs :many
SELECT * FROM iam_role_trust_principal_i_ds WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertRoleTrustPrincipalIDs :exec
INSERT INTO iam_role_trust_principal_i_ds (partition, account, resource_key, entry_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: GetRoleSourceRoleTemplate :one
SELECT * FROM iam_role_source_role_template WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertRoleSourceRoleTemplate :exec
INSERT INTO iam_role_source_role_template (partition, account, resource_key, arn, minor_version)
VALUES (?, ?, ?, ?, ?);

-- name: ListRoleSourceRoleTemplateParameters :many
SELECT * FROM iam_role_source_role_template_parameters WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_2;

-- name: InsertRoleSourceRoleTemplateParameters :exec
INSERT INTO iam_role_source_role_template_parameters (partition, account, resource_key, entry_2)
VALUES (?, ?, ?, ?);

-- name: ListRoleSourceRoleTemplateParametersValues :many
SELECT * FROM iam_role_source_role_template_parameters_values WHERE partition = ? AND account = ? AND resource_key = ? AND entry_2 = ? ORDER BY position_3;

-- name: InsertRoleSourceRoleTemplateParametersValues :exec
INSERT INTO iam_role_source_role_template_parameters_values (partition, account, resource_key, entry_2, position_3, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListRoleInline :many
SELECT * FROM iam_role_inline WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertRoleInline :exec
INSERT INTO iam_role_inline (partition, account, resource_key, entry_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: ListRoleAttached :many
SELECT * FROM iam_role_attached WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertRoleAttached :exec
INSERT INTO iam_role_attached (partition, account, resource_key, entry_1)
VALUES (?, ?, ?, ?);

-- name: GetManagedPolicy :one
SELECT * FROM iam_managed_policy WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertManagedPolicy :exec
INSERT INTO iam_managed_policy (partition, account, resource_key, policy_name, policy_id, arn, path, default_version_id, description, attachment_count, permissions_boundary_usage_count, next_version, is_attachable, create_date, update_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteManagedPolicy :execrows
DELETE FROM iam_managed_policy WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListManagedPolicyKeys :many
SELECT partition, account, resource_key FROM iam_managed_policy WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListManagedPolicyTags :many
SELECT * FROM iam_managed_policy_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertManagedPolicyTags :exec
INSERT INTO iam_managed_policy_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListManagedPolicyVersions :many
SELECT * FROM iam_managed_policy_versions WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY entry_1;

-- name: InsertManagedPolicyVersions :exec
INSERT INTO iam_managed_policy_versions (partition, account, resource_key, entry_1, document, version_id, is_default_version, create_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInstanceProfile :one
SELECT * FROM iam_instance_profile WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertInstanceProfile :exec
INSERT INTO iam_instance_profile (partition, account, resource_key, path, instance_profile_name, instance_profile_id, arn, role_id, create_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteInstanceProfile :execrows
DELETE FROM iam_instance_profile WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListInstanceProfileKeys :many
SELECT partition, account, resource_key FROM iam_instance_profile WHERE partition = ? AND account = ? ORDER BY instance_profile_name;

-- name: ListInstanceProfileTags :many
SELECT * FROM iam_instance_profile_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertInstanceProfileTags :exec
INSERT INTO iam_instance_profile_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLoginProfile :one
SELECT * FROM iam_login_profile WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertLoginProfile :exec
INSERT INTO iam_login_profile (partition, account, resource_key, user_id, create_date, password_changed_at, password_reset_required, password_algorithm, password_iterations, password_salt, password_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteLoginProfile :execrows
DELETE FROM iam_login_profile WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListLoginProfileKeys :many
SELECT partition, account, resource_key FROM iam_login_profile WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListLoginProfilePreviousPasswords :many
SELECT * FROM iam_login_profile_previous_passwords WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertLoginProfilePreviousPasswords :exec
INSERT INTO iam_login_profile_previous_passwords (partition, account, resource_key, position_1, algorithm, iterations, salt, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServiceCredential :one
SELECT * FROM iam_service_credential WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertServiceCredential :exec
INSERT INTO iam_service_credential (partition, account, resource_key, id, user_id, service_name, service_user_name, service_credential_alias, status, create_date, expiration_date, credential_age_days, secret_digest, slot)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteServiceCredential :execrows
DELETE FROM iam_service_credential WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListServiceCredentialKeys :many
SELECT partition, account, resource_key FROM iam_service_credential WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: GetSigningCertificate :one
SELECT * FROM iam_signing_certificate WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertSigningCertificate :exec
INSERT INTO iam_signing_certificate (partition, account, resource_key, id, user_id, body, status, der, upload_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteSigningCertificate :execrows
DELETE FROM iam_signing_certificate WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListSigningCertificateKeys :many
SELECT partition, account, resource_key FROM iam_signing_certificate WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: GetSSHPublicKey :one
SELECT * FROM iam_ssh_public_key WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertSSHPublicKey :exec
INSERT INTO iam_ssh_public_key (partition, account, resource_key, id, user_id, body, fingerprint, status, wire, upload_date)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteSSHPublicKey :execrows
DELETE FROM iam_ssh_public_key WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListSSHPublicKeyKeys :many
SELECT partition, account, resource_key FROM iam_ssh_public_key WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: GetServerCertificate :one
SELECT * FROM iam_server_certificate WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertServerCertificate :exec
INSERT INTO iam_server_certificate (partition, account, resource_key, id, name, path, arn, body, chain, private_key, upload_date, expiration, tagging_invalid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteServerCertificate :execrows
DELETE FROM iam_server_certificate WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListServerCertificateKeys :many
SELECT partition, account, resource_key FROM iam_server_certificate WHERE partition = ? AND account = ? ORDER BY name;

-- name: ListServerCertificateTags :many
SELECT * FROM iam_server_certificate_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertServerCertificateTags :exec
INSERT INTO iam_server_certificate_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetOIDCProvider :one
SELECT * FROM iam_oidc_provider WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertOIDCProvider :exec
INSERT INTO iam_oidc_provider (partition, account, resource_key, arn, id, url, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DeleteOIDCProvider :execrows
DELETE FROM iam_oidc_provider WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListOIDCProviderKeys :many
SELECT partition, account, resource_key FROM iam_oidc_provider WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListOIDCProviderClientIDs :many
SELECT * FROM iam_oidc_provider_client_i_ds WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertOIDCProviderClientIDs :exec
INSERT INTO iam_oidc_provider_client_i_ds (partition, account, resource_key, position_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: ListOIDCProviderThumbprints :many
SELECT * FROM iam_oidc_provider_thumbprints WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertOIDCProviderThumbprints :exec
INSERT INTO iam_oidc_provider_thumbprints (partition, account, resource_key, position_1, value)
VALUES (?, ?, ?, ?, ?);

-- name: ListOIDCProviderTags :many
SELECT * FROM iam_oidc_provider_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertOIDCProviderTags :exec
INSERT INTO iam_oidc_provider_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSAMLProvider :one
SELECT * FROM iam_saml_provider WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertSAMLProvider :exec
INSERT INTO iam_saml_provider (partition, account, resource_key, arn, name, uuid, metadata_document, assertion_encryption_mode, created_at, valid_until)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteSAMLProvider :execrows
DELETE FROM iam_saml_provider WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListSAMLProviderKeys :many
SELECT partition, account, resource_key FROM iam_saml_provider WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListSAMLProviderIssuers :many
SELECT * FROM iam_saml_provider_issuers WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertSAMLProviderIssuers :exec
INSERT INTO iam_saml_provider_issuers (partition, account, resource_key, position_1, entity_id)
VALUES (?, ?, ?, ?, ?);

-- name: ListSAMLProviderIssuersSigningCertificates :many
SELECT * FROM iam_saml_provider_issuers_signing_certificates WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? ORDER BY position_2;

-- name: InsertSAMLProviderIssuersSigningCertificates :exec
INSERT INTO iam_saml_provider_issuers_signing_certificates (partition, account, resource_key, position_1, position_2, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListSAMLProviderPrivateKeys :many
SELECT * FROM iam_saml_provider_private_keys WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertSAMLProviderPrivateKeys :exec
INSERT INTO iam_saml_provider_private_keys (partition, account, resource_key, position_1, id, created_at, pkcs8_der)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListSAMLProviderTags :many
SELECT * FROM iam_saml_provider_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertSAMLProviderTags :exec
INSERT INTO iam_saml_provider_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMFADevice :one
SELECT * FROM iam_mfa_device WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertMFADevice :exec
INSERT INTO iam_mfa_device (partition, account, resource_key, enable_date, retired_at, verification_count_window, last_pair_step, verification_count_count, serial_number, binding_value_seed, binding_value_user_id, binding_visible_value_seed, binding_visible_value_user_id, binding_value_skew_steps, binding_visible_value_skew_steps)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteMFADevice :execrows
DELETE FROM iam_mfa_device WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListMFADeviceKeys :many
SELECT partition, account, resource_key FROM iam_mfa_device WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListMFADeviceBindingPending :many
SELECT * FROM iam_mfa_device_binding_pending WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertMFADeviceBindingPending :exec
INSERT INTO iam_mfa_device_binding_pending (partition, account, resource_key, position_1, value_seed, value_user_id, value_skew_steps, visible_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListMFADeviceUsedCodes :many
SELECT * FROM iam_mfa_device_used_codes WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertMFADeviceUsedCodes :exec
INSERT INTO iam_mfa_device_used_codes (partition, account, resource_key, position_1, seed, step)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListMFADeviceTags :many
SELECT * FROM iam_mfa_device_tags WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertMFADeviceTags :exec
INSERT INTO iam_mfa_device_tags (partition, account, resource_key, position_1, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetServiceLinkedRoleDeletion :one
SELECT * FROM iam_service_linked_role_deletion WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertServiceLinkedRoleDeletion :exec
INSERT INTO iam_service_linked_role_deletion (partition, account, resource_key, id, role_id, role_arn, role_name, service_name, status, failure_reason, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteServiceLinkedRoleDeletion :execrows
DELETE FROM iam_service_linked_role_deletion WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: ListServiceLinkedRoleDeletionKeys :many
SELECT partition, account, resource_key FROM iam_service_linked_role_deletion WHERE partition = ? AND account = ? ORDER BY resource_key;

-- name: ListServiceLinkedRoleDeletionUsage :many
SELECT * FROM iam_service_linked_role_deletion_usage WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertServiceLinkedRoleDeletionUsage :exec
INSERT INTO iam_service_linked_role_deletion_usage (partition, account, resource_key, position_1, region)
VALUES (?, ?, ?, ?, ?);

-- name: ListServiceLinkedRoleDeletionUsageResourceARNs :many
SELECT * FROM iam_service_linked_role_deletion_usage_resource_ar_ns WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? ORDER BY position_2;

-- name: InsertServiceLinkedRoleDeletionUsageResourceARNs :exec
INSERT INTO iam_service_linked_role_deletion_usage_resource_ar_ns (partition, account, resource_key, position_1, position_2, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccountMetadata :one
SELECT * FROM iam_account_metadata WHERE partition = ? AND account = ?;

-- name: InsertAccountMetadata :exec
INSERT INTO iam_account_metadata (partition, account, created_at)
VALUES (?, ?, ?);

-- name: DeleteAccountMetadata :execrows
DELETE FROM iam_account_metadata WHERE partition = ? AND account = ?;

-- name: GetCredentialReport :one
SELECT * FROM iam_credential_report WHERE partition = ? AND account = ?;

-- name: InsertCredentialReport :exec
INSERT INTO iam_credential_report (partition, account, generation, state, requested_at, generated_at, content)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DeleteCredentialReport :execrows
DELETE FROM iam_credential_report WHERE partition = ? AND account = ?;

-- name: GetAccountSettings :one
SELECT * FROM iam_account_settings WHERE partition = ? AND account = ?;

-- name: InsertAccountSettings :exec
INSERT INTO iam_account_settings (partition, account, alias, role_manager_enabled, global_endpoint_all_regions_value, global_endpoint_all_regions_visible_value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteAccountSettings :execrows
DELETE FROM iam_account_settings WHERE partition = ? AND account = ?;

-- name: GetAccountSettingsPasswordPolicy :one
SELECT * FROM iam_account_settings_password_policy WHERE partition = ? AND account = ?;

-- name: InsertAccountSettingsPasswordPolicy :exec
INSERT INTO iam_account_settings_password_policy (partition, account, minimum_password_length, max_password_age, password_reuse_prevention, require_symbols, require_numbers, require_uppercase_characters, require_lowercase_characters, allow_users_to_change_password, hard_expiry)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccountSettingsRootLoginProfile :one
SELECT * FROM iam_account_settings_root_login_profile WHERE partition = ? AND account = ?;

-- name: InsertAccountSettingsRootLoginProfile :exec
INSERT INTO iam_account_settings_root_login_profile (partition, account, create_date)
VALUES (?, ?, ?);

-- name: GetAccountSettingsOutboundWebIdentity :one
SELECT * FROM iam_account_settings_outbound_web_identity WHERE partition = ? AND account = ?;

-- name: InsertAccountSettingsOutboundWebIdentity :exec
INSERT INTO iam_account_settings_outbound_web_identity (partition, account, issuer_id, issuer_url, rs256_id, es384_id, rs256_pkcs8_der, es384_pkcs8_der, enabled_value, enabled_visible_value)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAccountSettingsOutboundWebIdentityEnabled :many
SELECT * FROM iam_account_settings_outbound_web_identity_enabled WHERE partition = ? AND account = ? ORDER BY position_2;

-- name: InsertAccountSettingsOutboundWebIdentityEnabled :exec
INSERT INTO iam_account_settings_outbound_web_identity_enabled (partition, account, position_2, value, visible_at)
VALUES (?, ?, ?, ?, ?);

-- name: ListAccountSettingsGlobalEndpointAllRegions :many
SELECT * FROM iam_account_settings_global_endpoint_all_regions WHERE partition = ? AND account = ? ORDER BY position_1;

-- name: InsertAccountSettingsGlobalEndpointAllRegions :exec
INSERT INTO iam_account_settings_global_endpoint_all_regions (partition, account, position_1, value, visible_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetAccessReport :one
SELECT * FROM iam_access_report WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertAccessReport :exec
INSERT INTO iam_access_report (partition, account, resource_key, id, owner, granularity, requested_at, completed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteAccessReport :execrows
DELETE FROM iam_access_report WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: PendingAccessReportKeys :many
SELECT resource_key FROM iam_access_report WHERE partition = ? AND account = ? AND completed_at IS NULL ORDER BY resource_key;

-- name: OrganizationAccessReportCandidates :many
SELECT r.resource_key, r.requested_at FROM iam_access_report AS r
JOIN iam_access_report_organization AS o USING (partition, account, resource_key)
WHERE r.partition = ? AND r.account = ? AND r.owner = ? AND o.entity_path = ? AND o.policy_id = ?;

-- name: ListAccessReportServices :many
SELECT * FROM iam_access_report_services WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_1;

-- name: InsertAccessReportServices :exec
INSERT INTO iam_access_report_services (partition, account, resource_key, position_1, namespace, name)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccessReportServicesLastActivity :one
SELECT * FROM iam_access_report_services_last_activity WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ?;

-- name: InsertAccessReportServicesLastActivity :exec
INSERT INTO iam_access_report_services_last_activity (partition, account, resource_key, position_1, principal_id, principal_arn, service_namespace, action_name, region, last_authenticated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAccessReportServicesActions :many
SELECT * FROM iam_access_report_services_actions WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? ORDER BY position_2;

-- name: InsertAccessReportServicesActions :exec
INSERT INTO iam_access_report_services_actions (partition, account, resource_key, position_1, position_2, name)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccessReportServicesActionsLastActivity :one
SELECT * FROM iam_access_report_services_actions_last_activity WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? AND position_2 = ?;

-- name: InsertAccessReportServicesActionsLastActivity :exec
INSERT INTO iam_access_report_services_actions_last_activity (partition, account, resource_key, position_1, position_2, principal_id, principal_arn, service_namespace, action_name, region, last_authenticated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAccessReportServicesEntities :many
SELECT * FROM iam_access_report_services_entities WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? ORDER BY position_2;

-- name: InsertAccessReportServicesEntities :exec
INSERT INTO iam_access_report_services_entities (partition, account, resource_key, position_1, position_2, id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetAccessReportServicesEntitiesLastActivity :one
SELECT * FROM iam_access_report_services_entities_last_activity WHERE partition = ? AND account = ? AND resource_key = ? AND position_1 = ? AND position_2 = ?;

-- name: InsertAccessReportServicesEntitiesLastActivity :exec
INSERT INTO iam_access_report_services_entities_last_activity (partition, account, resource_key, position_1, position_2, principal_id, principal_arn, service_namespace, action_name, region, last_authenticated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccessReportOrganization :one
SELECT * FROM iam_access_report_organization WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertAccessReportOrganization :exec
INSERT INTO iam_access_report_organization (partition, account, resource_key, entity_path, policy_id)
VALUES (?, ?, ?, ?, ?);

-- name: ListAccessReportOrganizationServices :many
SELECT * FROM iam_access_report_organization_services WHERE partition = ? AND account = ? AND resource_key = ? ORDER BY position_2;

-- name: InsertAccessReportOrganizationServices :exec
INSERT INTO iam_access_report_organization_services (partition, account, resource_key, position_2, namespace, name, authenticated_accounts)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetAccessReportOrganizationServicesLastActivity :one
SELECT * FROM iam_access_report_organization_services_last_activity WHERE partition = ? AND account = ? AND resource_key = ? AND position_2 = ?;

-- name: InsertAccessReportOrganizationServicesLastActivity :exec
INSERT INTO iam_access_report_organization_services_last_activity (partition, account, resource_key, position_2, entity_path, region, last_authenticated)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetAccessReportOrganizationError :one
SELECT * FROM iam_access_report_organization_error WHERE partition = ? AND account = ? AND resource_key = ?;

-- name: InsertAccessReportOrganizationError :exec
INSERT INTO iam_access_report_organization_error (partition, account, resource_key, code, message)
VALUES (?, ?, ?, ?, ?);

-- name: GetPrincipalActivity :one
SELECT * FROM iam_principal_activity WHERE partition = ? AND account = ? AND key_principal_id = ? AND key_service_namespace = ? AND key_action_name = ? AND key_region = ?;

-- name: InsertPrincipalActivity :exec
INSERT INTO iam_principal_activity (partition, account, key_principal_id, key_service_namespace, key_action_name, key_region, principal_id, principal_arn, service_namespace, action_name, region, last_authenticated)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeletePrincipalActivity :execrows
DELETE FROM iam_principal_activity WHERE partition = ? AND account = ? AND key_principal_id = ? AND key_service_namespace = ? AND key_action_name = ? AND key_region = ?;

-- name: ListPrincipalActivityKeys :many
SELECT partition, account, key_principal_id, key_service_namespace, key_action_name, key_region FROM iam_principal_activity WHERE partition = ? AND account = ? ORDER BY key_principal_id, key_service_namespace, key_action_name, key_region;

-- name: GetCredential :one
SELECT * FROM iam_credential WHERE resource_key = ?;

-- name: InsertCredential :exec
INSERT INTO iam_credential (resource_key, credential_access_key_id, credential_secret_access_key, credential_session_token, credential_account_id, credential_principal_arn, credential_principal_id, credential_user_name, credential_issuer_arn, credential_issuer_id, credential_federated_provider, credential_source_identity, last_used_service, last_used_region, credential_default_regions_only, credential_has_session_policy, credential_mfa_present, credential_expiration, credential_create_date, credential_mfa_authenticated_at, last_used_date, credential_session_type, status, credential_request_parent_event_id, credential_in_scope_of_issuer_type, credential_in_scope_of_credentials_issued_to)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteCredential :execrows
DELETE FROM iam_credential WHERE resource_key = ?;

-- name: ListCredentialKeys :many
SELECT resource_key FROM iam_credential WHERE credential_account_id = ? AND (credential_principal_id = ? OR credential_issuer_id = ?) ORDER BY resource_key;

-- name: ListCredentialSessionPolicies :many
SELECT * FROM iam_credential_session_policies WHERE resource_key = ? ORDER BY position_1;

-- name: InsertCredentialSessionPolicies :exec
INSERT INTO iam_credential_session_policies (resource_key, position_1, value)
VALUES (?, ?, ?);

-- name: ListCredentialSessionPolicyARNs :many
SELECT * FROM iam_credential_session_policy_ar_ns WHERE resource_key = ? ORDER BY position_1;

-- name: InsertCredentialSessionPolicyARNs :exec
INSERT INTO iam_credential_session_policy_ar_ns (resource_key, position_1, value)
VALUES (?, ?, ?);

-- name: ListCredentialSessionContext :many
SELECT * FROM iam_credential_session_context WHERE resource_key = ? ORDER BY entry_1;

-- name: InsertCredentialSessionContext :exec
INSERT INTO iam_credential_session_context (resource_key, entry_1)
VALUES (?, ?);

-- name: ListCredentialSessionContextValues :many
SELECT * FROM iam_credential_session_context_values WHERE resource_key = ? AND entry_1 = ? ORDER BY position_2;

-- name: InsertCredentialSessionContextValues :exec
INSERT INTO iam_credential_session_context_values (resource_key, entry_1, position_2, value)
VALUES (?, ?, ?, ?);

-- name: ListCredentialSessionTags :many
SELECT * FROM iam_credential_session_tags WHERE resource_key = ? ORDER BY entry_1;

-- name: InsertCredentialSessionTags :exec
INSERT INTO iam_credential_session_tags (resource_key, entry_1, value)
VALUES (?, ?, ?);

-- name: ListCredentialTransitiveTagKeys :many
SELECT * FROM iam_credential_transitive_tag_keys WHERE resource_key = ? ORDER BY position_1;

-- name: InsertCredentialTransitiveTagKeys :exec
INSERT INTO iam_credential_transitive_tag_keys (resource_key, position_1, value)
VALUES (?, ?, ?);

-- name: CredentialReportScopes :many
SELECT DISTINCT partition, account FROM iam_credential_report ORDER BY partition, account;

-- name: AccessReportScopes :many
SELECT DISTINCT partition, account FROM iam_access_report ORDER BY partition, account;

-- name: ServiceLinkedRoleDeletionScopes :many
SELECT DISTINCT partition, account FROM iam_service_linked_role_deletion ORDER BY partition, account;

-- name: AccountAliasOwner :one
SELECT account FROM iam_account_settings WHERE partition = ? AND alias = ? AND alias != '' ORDER BY account LIMIT 1;
