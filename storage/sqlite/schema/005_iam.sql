-- IAM owns identities, authentication material and policy/report relationships.

CREATE TABLE iam_scopes (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    PRIMARY KEY (partition, account)
);

CREATE TABLE iam_user (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    path TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    password_last_used TIMESTAMP,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_user_permissions_boundary (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    permissions_boundary_type TEXT NOT NULL,
    permissions_boundary_arn TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_user(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_user_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_user(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_user_inline (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_user(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_user_attached (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_user(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_group (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    path TEXT NOT NULL,
    group_name TEXT NOT NULL,
    group_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_group_inline (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_group(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_group_attached (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_group(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_group_members (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_group(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    path TEXT NOT NULL,
    role_name TEXT NOT NULL,
    role_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    assume_role_policy_document TEXT NOT NULL,
    description TEXT NOT NULL,
    service_linked_service TEXT NOT NULL,
    last_used_region TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    last_used_date TIMESTAMP NOT NULL,
    max_session_duration INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_role_permissions_boundary (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    permissions_boundary_type TEXT NOT NULL,
    permissions_boundary_arn TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_trust_principal_i_ds (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_source_role_template (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    arn TEXT NOT NULL,
    minor_version INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_source_role_template_parameters (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_2 TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_2),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role_source_role_template(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_source_role_template_parameters_values (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_2 TEXT NOT NULL,
    position_3 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_2, position_3),
    FOREIGN KEY (partition, account, resource_key, entry_2) REFERENCES iam_role_source_role_template_parameters(partition, account, resource_key, entry_2) ON DELETE CASCADE
);

CREATE TABLE iam_role_inline (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_role_attached (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_role(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_managed_policy (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    path TEXT NOT NULL,
    default_version_id TEXT NOT NULL,
    description TEXT NOT NULL,
    attachment_count INTEGER NOT NULL,
    permissions_boundary_usage_count INTEGER NOT NULL,
    next_version INTEGER NOT NULL,
    is_attachable BOOLEAN NOT NULL,
    create_date TIMESTAMP NOT NULL,
    update_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_managed_policy_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_managed_policy(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_managed_policy_versions (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    document TEXT NOT NULL,
    version_id TEXT NOT NULL,
    is_default_version BOOLEAN NOT NULL,
    create_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, entry_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_managed_policy(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_instance_profile (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    path TEXT NOT NULL,
    instance_profile_name TEXT NOT NULL,
    instance_profile_id TEXT NOT NULL,
    arn TEXT NOT NULL,
    role_id TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_instance_profile_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_instance_profile(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_login_profile (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    user_id TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    password_changed_at TIMESTAMP NOT NULL,
    password_reset_required BOOLEAN NOT NULL,
    password_algorithm TEXT NOT NULL,
    password_iterations INTEGER NOT NULL,
    password_salt BLOB,
    password_hash BLOB,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_login_profile_previous_passwords (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    salt BLOB,
    hash BLOB,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_login_profile(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_service_credential (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    service_user_name TEXT NOT NULL,
    service_credential_alias TEXT NOT NULL,
    status TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    expiration_date TIMESTAMP,
    credential_age_days INTEGER NOT NULL,
    secret_digest BLOB NOT NULL,
    slot INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_signing_certificate (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,
    der BLOB,
    upload_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_ssh_public_key (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    body TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    wire BLOB,
    upload_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_server_certificate (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    arn TEXT NOT NULL,
    body TEXT NOT NULL,
    chain TEXT NOT NULL,
    private_key BLOB,
    upload_date TIMESTAMP NOT NULL,
    expiration TIMESTAMP NOT NULL,
    tagging_invalid BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_server_certificate_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_server_certificate(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_oidc_provider (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    arn TEXT NOT NULL,
    id TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_oidc_provider_client_i_ds (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_oidc_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_oidc_provider_thumbprints (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_oidc_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_oidc_provider_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_oidc_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_saml_provider (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    arn TEXT NOT NULL,
    name TEXT NOT NULL,
    uuid TEXT NOT NULL,
    metadata_document TEXT NOT NULL,
    assertion_encryption_mode TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_saml_provider_issuers (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_saml_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_saml_provider_issuers_signing_certificates (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    value BLOB,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1) REFERENCES iam_saml_provider_issuers(partition, account, resource_key, position_1) ON DELETE CASCADE
);

CREATE TABLE iam_saml_provider_private_keys (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    pkcs8_der BLOB,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_saml_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_saml_provider_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_saml_provider(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_mfa_device (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    enable_date TIMESTAMP NOT NULL,
    retired_at TIMESTAMP NOT NULL,
    verification_count_window TIMESTAMP NOT NULL,
    last_pair_step INTEGER,
    verification_count_count INTEGER NOT NULL,
    serial_number TEXT NOT NULL,
    binding_value_seed TEXT NOT NULL,
    binding_value_user_id TEXT NOT NULL,
    binding_visible_value_seed TEXT NOT NULL,
    binding_visible_value_user_id TEXT NOT NULL,
    binding_value_skew_steps INTEGER NOT NULL,
    binding_visible_value_skew_steps INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_mfa_device_binding_pending (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value_seed TEXT NOT NULL,
    value_user_id TEXT NOT NULL,
    value_skew_steps INTEGER NOT NULL,
    visible_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_mfa_device(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_mfa_device_used_codes (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    seed TEXT NOT NULL,
    step INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_mfa_device(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_mfa_device_tags (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_mfa_device(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_service_linked_role_deletion (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    role_name TEXT NOT NULL,
    service_name TEXT NOT NULL,
    status TEXT NOT NULL,
    failure_reason TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_service_linked_role_deletion_usage (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    region TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_service_linked_role_deletion(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_service_linked_role_deletion_usage_resource_ar_ns (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1) REFERENCES iam_service_linked_role_deletion_usage(partition, account, resource_key, position_1) ON DELETE CASCADE
);

CREATE TABLE iam_account_metadata (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account)
);

CREATE TABLE iam_credential_report (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    generation BLOB NOT NULL,
    state TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    generated_at TIMESTAMP NOT NULL,
    content BLOB,
    PRIMARY KEY (partition, account)
);

CREATE TABLE iam_account_settings (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    alias TEXT NOT NULL,
    role_manager_enabled BOOLEAN NOT NULL,
    global_endpoint_all_regions_value BOOLEAN NOT NULL,
    global_endpoint_all_regions_visible_value BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account)
);

CREATE TABLE iam_account_settings_password_policy (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    minimum_password_length INTEGER NOT NULL,
    max_password_age INTEGER NOT NULL,
    password_reuse_prevention INTEGER NOT NULL,
    require_symbols BOOLEAN NOT NULL,
    require_numbers BOOLEAN NOT NULL,
    require_uppercase_characters BOOLEAN NOT NULL,
    require_lowercase_characters BOOLEAN NOT NULL,
    allow_users_to_change_password BOOLEAN NOT NULL,
    hard_expiry BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account),
    FOREIGN KEY (partition, account) REFERENCES iam_account_settings(partition, account) ON DELETE CASCADE
);

CREATE TABLE iam_account_settings_root_login_profile (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    create_date TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account),
    FOREIGN KEY (partition, account) REFERENCES iam_account_settings(partition, account) ON DELETE CASCADE
);

CREATE TABLE iam_account_settings_outbound_web_identity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    issuer_url TEXT NOT NULL,
    rs256_id TEXT NOT NULL,
    es384_id TEXT NOT NULL,
    rs256_pkcs8_der BLOB,
    es384_pkcs8_der BLOB,
    enabled_value BOOLEAN NOT NULL,
    enabled_visible_value BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account),
    FOREIGN KEY (partition, account) REFERENCES iam_account_settings(partition, account) ON DELETE CASCADE
);

CREATE TABLE iam_account_settings_outbound_web_identity_enabled (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    position_2 INTEGER NOT NULL,
    value BOOLEAN NOT NULL,
    visible_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, position_2),
    FOREIGN KEY (partition, account) REFERENCES iam_account_settings_outbound_web_identity(partition, account) ON DELETE CASCADE
);

CREATE TABLE iam_account_settings_global_endpoint_all_regions (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value BOOLEAN NOT NULL,
    visible_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, position_1),
    FOREIGN KEY (partition, account) REFERENCES iam_account_settings(partition, account) ON DELETE CASCADE
);

CREATE TABLE iam_access_report (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    id TEXT NOT NULL,
    owner TEXT NOT NULL,
    granularity TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    PRIMARY KEY (partition, account, resource_key)
);

CREATE TABLE iam_access_report_services (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_access_report(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_services_last_activity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    service_namespace TEXT NOT NULL,
    action_name TEXT NOT NULL,
    region TEXT NOT NULL,
    last_authenticated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1),
    FOREIGN KEY (partition, account, resource_key, position_1) REFERENCES iam_access_report_services(partition, account, resource_key, position_1) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_services_actions (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1) REFERENCES iam_access_report_services(partition, account, resource_key, position_1) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_services_actions_last_activity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    service_namespace TEXT NOT NULL,
    action_name TEXT NOT NULL,
    region TEXT NOT NULL,
    last_authenticated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1, position_2) REFERENCES iam_access_report_services_actions(partition, account, resource_key, position_1, position_2) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_services_entities (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    id TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1) REFERENCES iam_access_report_services(partition, account, resource_key, position_1) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_services_entities_last_activity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    position_2 INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    service_namespace TEXT NOT NULL,
    action_name TEXT NOT NULL,
    region TEXT NOT NULL,
    last_authenticated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_1, position_2),
    FOREIGN KEY (partition, account, resource_key, position_1, position_2) REFERENCES iam_access_report_services_entities(partition, account, resource_key, position_1, position_2) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_organization (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    entity_path TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_access_report(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_organization_services (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_2 INTEGER NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    authenticated_accounts INTEGER NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_2),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_access_report_organization(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_organization_services_last_activity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    position_2 INTEGER NOT NULL,
    entity_path TEXT NOT NULL,
    region TEXT NOT NULL,
    last_authenticated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, resource_key, position_2),
    FOREIGN KEY (partition, account, resource_key, position_2) REFERENCES iam_access_report_organization_services(partition, account, resource_key, position_2) ON DELETE CASCADE
);

CREATE TABLE iam_access_report_organization_error (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (partition, account, resource_key),
    FOREIGN KEY (partition, account, resource_key) REFERENCES iam_access_report_organization(partition, account, resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_principal_activity (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    key_principal_id TEXT NOT NULL,
    key_service_namespace TEXT NOT NULL,
    key_action_name TEXT NOT NULL,
    key_region TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    service_namespace TEXT NOT NULL,
    action_name TEXT NOT NULL,
    region TEXT NOT NULL,
    last_authenticated TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, key_principal_id, key_service_namespace, key_action_name, key_region)
);

CREATE TABLE iam_credential (
    resource_key TEXT NOT NULL,
    credential_access_key_id TEXT NOT NULL,
    credential_secret_access_key TEXT NOT NULL,
    credential_session_token TEXT NOT NULL,
    credential_account_id TEXT NOT NULL,
    credential_principal_arn TEXT NOT NULL,
    credential_principal_id TEXT NOT NULL,
    credential_user_name TEXT NOT NULL,
    credential_issuer_arn TEXT NOT NULL,
    credential_issuer_id TEXT NOT NULL,
    credential_federated_provider TEXT NOT NULL,
    credential_source_identity TEXT NOT NULL,
    last_used_service TEXT NOT NULL,
    last_used_region TEXT NOT NULL,
    credential_default_regions_only BOOLEAN NOT NULL,
    credential_has_session_policy BOOLEAN NOT NULL,
    credential_mfa_present BOOLEAN NOT NULL,
    credential_expiration TIMESTAMP NOT NULL,
    credential_create_date TIMESTAMP NOT NULL,
    credential_mfa_authenticated_at TIMESTAMP NOT NULL,
    last_used_date TIMESTAMP NOT NULL,
    credential_session_type TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (resource_key)
);

CREATE TABLE iam_credential_session_policies (
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (resource_key, position_1),
    FOREIGN KEY (resource_key) REFERENCES iam_credential(resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_credential_session_policy_ar_ns (
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (resource_key, position_1),
    FOREIGN KEY (resource_key) REFERENCES iam_credential(resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_credential_session_context (
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    PRIMARY KEY (resource_key, entry_1),
    FOREIGN KEY (resource_key) REFERENCES iam_credential(resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_credential_session_context_values (
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    position_2 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (resource_key, entry_1, position_2),
    FOREIGN KEY (resource_key, entry_1) REFERENCES iam_credential_session_context(resource_key, entry_1) ON DELETE CASCADE
);

CREATE TABLE iam_credential_session_tags (
    resource_key TEXT NOT NULL,
    entry_1 TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (resource_key, entry_1),
    FOREIGN KEY (resource_key) REFERENCES iam_credential(resource_key) ON DELETE CASCADE
);

CREATE TABLE iam_credential_transitive_tag_keys (
    resource_key TEXT NOT NULL,
    position_1 INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (resource_key, position_1),
    FOREIGN KEY (resource_key) REFERENCES iam_credential(resource_key) ON DELETE CASCADE
);
