-- SSM Parameter Store keeps values separate from metadata and retains typed caller authority.

CREATE TABLE ssm_parameters (
    id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    arn TEXT NOT NULL,
    type TEXT NOT NULL,
    tier TEXT NOT NULL,
    data_type TEXT NOT NULL,
    description TEXT NOT NULL,
    allowed_pattern TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    tags_present BOOLEAN NOT NULL,
    policies_present BOOLEAN NOT NULL,
    resource_policies_present BOOLEAN NOT NULL,
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE ssm_tags (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_parameters(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE ssm_resource_policies (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_parameters(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    hash TEXT NOT NULL,
    document TEXT NOT NULL,
    trust_policy BOOLEAN NOT NULL,
    principals_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_resource_policy_bindings (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_resource_policies(id) ON DELETE CASCADE,
    arn TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    UNIQUE (parent_id, arn)
);

CREATE TABLE ssm_versions (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_parameters(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    type TEXT NOT NULL,
    tier TEXT NOT NULL,
    data_type TEXT NOT NULL,
    description TEXT NOT NULL,
    allowed_pattern TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_arn TEXT NOT NULL,
    modified_user TEXT NOT NULL,
    modified DATETIME NOT NULL,
    labels_present BOOLEAN NOT NULL,
    policies_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, version)
);

CREATE TABLE ssm_values (
    parent_id INTEGER PRIMARY KEY REFERENCES ssm_versions(id) ON DELETE CASCADE,
    value BLOB,
    wrapped_key BLOB
);

CREATE TABLE ssm_labels (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_versions(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_parameter_policies (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_parameters(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    type TEXT NOT NULL,
    version TEXT NOT NULL,
    attributes_present BOOLEAN NOT NULL,
    due DATETIME,
    fired BOOLEAN NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_parameter_policy_attributes (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_parameter_policies(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE ssm_version_policies (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_versions(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    type TEXT NOT NULL,
    version TEXT NOT NULL,
    attributes_present BOOLEAN NOT NULL,
    due DATETIME,
    fired BOOLEAN NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_version_policy_attributes (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_version_policies(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE INDEX ssm_parameter_policies_due ON ssm_parameter_policies(due, parent_id) WHERE due IS NOT NULL AND fired = 0;

CREATE TABLE ssm_settings (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    setting_id TEXT NOT NULL,
    value TEXT NOT NULL,
    modified_user TEXT NOT NULL,
    modified DATETIME NOT NULL,
    PRIMARY KEY (partition, account_id, region, setting_id)
);

CREATE TABLE ssm_validation_jobs (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL UNIQUE REFERENCES ssm_versions(id) ON DELETE CASCADE,
    due DATETIME NOT NULL,
    caller_account_id TEXT NOT NULL,
    caller_region TEXT NOT NULL,
    caller_partition TEXT NOT NULL,
    caller_access_key_id TEXT NOT NULL,
    caller_request_id TEXT NOT NULL,
    caller_parent_event_id TEXT NOT NULL,
    caller_trace_header TEXT NOT NULL,
    caller_principal_arn TEXT NOT NULL,
    caller_principal_id TEXT NOT NULL,
    caller_user_name TEXT NOT NULL,
    caller_session_type TEXT NOT NULL,
    caller_issuer_arn TEXT NOT NULL,
    caller_issuer_id TEXT NOT NULL,
    caller_has_session_policy BOOLEAN NOT NULL,
    caller_federated_provider TEXT NOT NULL,
    caller_source_identity TEXT NOT NULL,
    caller_mfa_present BOOLEAN NOT NULL,
    caller_mfa_authenticated_at DATETIME NOT NULL,
    caller_token_issue_time DATETIME NOT NULL,
    caller_transport_known BOOLEAN NOT NULL,
    caller_source_ip TEXT NOT NULL,
    caller_secure_transport BOOLEAN NOT NULL,
    caller_user_agent TEXT NOT NULL,
    caller_signature_version TEXT NOT NULL,
    caller_authentication_method TEXT NOT NULL,
    caller_service_principal_name TEXT NOT NULL,
    caller_service_principal_source_arn TEXT NOT NULL,
    caller_service_principal_type TEXT NOT NULL,
    caller_invoked_by TEXT NOT NULL,
    caller_in_scope_of_issuer_type TEXT NOT NULL,
    caller_in_scope_of_credentials_issued_to TEXT NOT NULL,
    caller_session_policies_present BOOLEAN NOT NULL,
    caller_session_policy_arns_present BOOLEAN NOT NULL,
    caller_transitive_tag_keys_present BOOLEAN NOT NULL,
    caller_called_via_present BOOLEAN NOT NULL,
    caller_service_principal_aliases_present BOOLEAN NOT NULL,
    caller_session_context_present BOOLEAN NOT NULL,
    caller_session_tags_present BOOLEAN NOT NULL
);

CREATE INDEX ssm_validation_jobs_due ON ssm_validation_jobs(due, parent_id);

CREATE TABLE ssm_caller_session_policies (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_caller_session_policy_arns (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_caller_transitive_tag_keys (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_caller_called_via (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_caller_service_principal_aliases (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE ssm_caller_session_tags (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE ssm_caller_session_context (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_validation_jobs(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE ssm_caller_session_context_values (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES ssm_caller_session_context(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);
