-- Athena retains typed API metadata and work intent. S3 owns result bytes.
-- Presence columns distinguish nil, empty containers, and zero-valued pointers.
CREATE TABLE athena_queries (
    id INTEGER PRIMARY KEY,
    key_scope_partition TEXT NOT NULL,
    key_scope_account_id TEXT NOT NULL,
    key_scope_region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    data_engine_version_present BOOLEAN NOT NULL,
    data_engine_version_effective_engine_version TEXT,
    data_engine_version_selected_engine_version TEXT,
    data_execution_parameters_present BOOLEAN NOT NULL,
    data_managed_query_results_configuration_present BOOLEAN NOT NULL,
    data_managed_query_results_configuration_enabled BOOLEAN,
    data_managed_query_results_configuration_encryption_configuration_present BOOLEAN NOT NULL,
    data_managed_query_results_configuration_encryption_configuration_kms_key TEXT,
    data_query TEXT,
    data_query_execution_context_present BOOLEAN NOT NULL,
    data_query_execution_context_catalog TEXT,
    data_query_execution_context_database TEXT,
    data_query_execution_id TEXT,
    data_query_results_s3_access_grants_configuration_present BOOLEAN NOT NULL,
    data_query_results_s3_access_grants_configuration_authentication_type TEXT,
    data_query_results_s3_access_grants_configuration_create_user_level_prefix BOOLEAN,
    data_query_results_s3_access_grants_configuration_enable_s3_access_grants BOOLEAN,
    data_result_configuration_present BOOLEAN NOT NULL,
    data_result_configuration_acl_configuration_present BOOLEAN NOT NULL,
    data_result_configuration_acl_configuration_s3_acl_option TEXT,
    data_result_configuration_encryption_configuration_present BOOLEAN NOT NULL,
    data_result_configuration_encryption_configuration_encryption_option TEXT,
    data_result_configuration_encryption_configuration_kms_key TEXT,
    data_result_configuration_expected_bucket_owner TEXT,
    data_result_configuration_output_location TEXT,
    data_result_reuse_configuration_present BOOLEAN NOT NULL,
    data_result_reuse_configuration_result_reuse_by_age_configuration_present BOOLEAN NOT NULL,
    data_result_reuse_configuration_result_reuse_by_age_configuration_enabled BOOLEAN,
    data_result_reuse_configuration_result_reuse_by_age_configuration_max_age_in_minutes INTEGER,
    data_statement_type TEXT,
    data_statistics_present BOOLEAN NOT NULL,
    data_statistics_data_manifest_location TEXT,
    data_statistics_data_scanned_in_bytes INTEGER,
    data_statistics_dpu_count REAL,
    data_statistics_engine_execution_time_in_millis INTEGER,
    data_statistics_query_planning_time_in_millis INTEGER,
    data_statistics_query_queue_time_in_millis INTEGER,
    data_statistics_result_reuse_information_present BOOLEAN NOT NULL,
    data_statistics_result_reuse_information_reused_previous_result BOOLEAN,
    data_statistics_service_pre_processing_time_in_millis INTEGER,
    data_statistics_service_processing_time_in_millis INTEGER,
    data_statistics_total_execution_time_in_millis INTEGER,
    data_status_present BOOLEAN NOT NULL,
    data_status_athena_error_present BOOLEAN NOT NULL,
    data_status_athena_error_error_category INTEGER,
    data_status_athena_error_error_message TEXT,
    data_status_athena_error_error_type INTEGER,
    data_status_athena_error_retryable BOOLEAN,
    data_status_completion_date_time DATETIME,
    data_status_state TEXT,
    data_status_state_change_reason TEXT,
    data_status_submission_date_time DATETIME,
    data_substatement_type TEXT,
    data_work_group TEXT,
    token TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
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
    caller_session_policies_present BOOLEAN NOT NULL,
    caller_session_policy_ar_ns_present BOOLEAN NOT NULL,
    caller_has_session_policy BOOLEAN NOT NULL,
    caller_session_context_present BOOLEAN NOT NULL,
    caller_federated_provider TEXT NOT NULL,
    caller_session_tags_present BOOLEAN NOT NULL,
    caller_transitive_tag_keys_present BOOLEAN NOT NULL,
    caller_source_identity TEXT NOT NULL,
    caller_mfa_present BOOLEAN NOT NULL,
    caller_mfa_authenticated_at DATETIME NOT NULL,
    caller_token_issue_time DATETIME NOT NULL,
    caller_called_via_present BOOLEAN NOT NULL,
    caller_transport_known BOOLEAN NOT NULL,
    caller_source_ip TEXT NOT NULL,
    caller_secure_transport BOOLEAN NOT NULL,
    caller_user_agent TEXT NOT NULL,
    caller_signature_version TEXT NOT NULL,
    caller_authentication_method TEXT NOT NULL,
    caller_service_principal_name TEXT NOT NULL,
    caller_service_principal_source_arn TEXT NOT NULL,
    caller_service_principal_type TEXT NOT NULL,
    caller_service_principal_aliases_present BOOLEAN NOT NULL,
    caller_invoked_by TEXT NOT NULL,
    caller_in_scope_of_issuer_type TEXT NOT NULL,
    caller_in_scope_of_credentials_issued_to TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    due DATETIME NOT NULL,
    started DATETIME,
    engine_id TEXT NOT NULL,
    columns_present BOOLEAN NOT NULL,
    update_count INTEGER NOT NULL,
    publish_metrics BOOLEAN NOT NULL,
    requester_pays BOOLEAN NOT NULL,
    bytes_cutoff INTEGER NOT NULL,
    UNIQUE (key_scope_partition, key_scope_account_id, key_scope_region, key_name)
);
CREATE UNIQUE INDEX athena_queries_token ON athena_queries(key_scope_partition, key_scope_account_id, key_scope_region, token) WHERE token <> '';
CREATE INDEX athena_queries_due ON athena_queries(due, key_name, key_scope_partition, key_scope_account_id, key_scope_region) WHERE data_status_state = 'QUEUED' OR (data_status_state IN ('FAILED', 'CANCELLED') AND engine_id <> '');
CREATE INDEX athena_queries_active ON athena_queries(key_name, key_scope_partition, key_scope_account_id, key_scope_region) WHERE data_status_state IN ('QUEUED', 'RUNNING') OR engine_id <> '';

CREATE TABLE athena_queries_data_execution_parameters (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_session_policies (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_session_policy_ar_ns (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_session_context (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_queries_caller_session_context_value (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries_caller_session_context(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_session_tags (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_queries_caller_transitive_tag_keys (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_called_via (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_caller_service_principal_aliases (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_queries_columns (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_queries(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value_case_sensitive BOOLEAN,
    value_catalog_name TEXT,
    value_label TEXT,
    value_name TEXT,
    value_nullable TEXT,
    value_precision INTEGER,
    value_scale INTEGER,
    value_schema_name TEXT,
    value_table_name TEXT,
    value_type TEXT,
    UNIQUE (parent_id, position)
);

