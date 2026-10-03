-- Athena retains typed API metadata and work intent. S3 owns result bytes.
-- Presence columns distinguish nil, empty containers, and zero-valued pointers.
CREATE TABLE athena_work_groups (
    id INTEGER PRIMARY KEY,
    key_scope_partition TEXT NOT NULL,
    key_scope_account_id TEXT NOT NULL,
    key_scope_region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    data_configuration_present BOOLEAN NOT NULL,
    data_configuration_additional_configuration TEXT,
    data_configuration_bytes_scanned_cutoff_per_query INTEGER,
    data_configuration_customer_content_encryption_configuration_present BOOLEAN NOT NULL,
    data_configuration_customer_content_encryption_configuration_kms_key TEXT,
    data_configuration_enable_minimum_encryption_configuration BOOLEAN,
    data_configuration_enforce_work_group_configuration BOOLEAN,
    data_configuration_engine_configuration_present BOOLEAN NOT NULL,
    data_configuration_engine_configuration_additional_configs_present BOOLEAN NOT NULL,
    data_configuration_engine_configuration_classifications_present BOOLEAN NOT NULL,
    data_configuration_engine_configuration_coordinator_dpu_size INTEGER,
    data_configuration_engine_configuration_default_executor_dpu_size INTEGER,
    data_configuration_engine_configuration_max_concurrent_dpus INTEGER,
    data_configuration_engine_configuration_spark_properties_present BOOLEAN NOT NULL,
    data_configuration_engine_version_present BOOLEAN NOT NULL,
    data_configuration_engine_version_effective_engine_version TEXT,
    data_configuration_engine_version_selected_engine_version TEXT,
    data_configuration_execution_role TEXT,
    data_configuration_identity_center_configuration_present BOOLEAN NOT NULL,
    data_configuration_identity_center_configuration_enable_identity_center BOOLEAN,
    data_configuration_identity_center_configuration_identity_center_instance_arn TEXT,
    data_configuration_managed_query_results_configuration_present BOOLEAN NOT NULL,
    data_configuration_managed_query_results_configuration_enabled BOOLEAN,
    data_configuration_managed_query_results_configuration_encryption_configuration_present BOOLEAN NOT NULL,
    data_configuration_managed_query_results_configuration_encryption_configuration_kms_key TEXT,
    data_configuration_monitoring_configuration_present BOOLEAN NOT NULL,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_present BOOLEAN NOT NULL,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_enabled BOOLEAN,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_group TEXT,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_stream_name_prefix TEXT,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_present BOOLEAN NOT NULL,
    data_configuration_monitoring_configuration_managed_logging_configuration_present BOOLEAN NOT NULL,
    data_configuration_monitoring_configuration_managed_logging_configuration_enabled BOOLEAN,
    data_configuration_monitoring_configuration_managed_logging_configuration_kms_key TEXT,
    data_configuration_monitoring_configuration_s3_logging_configuration_present BOOLEAN NOT NULL,
    data_configuration_monitoring_configuration_s3_logging_configuration_enabled BOOLEAN,
    data_configuration_monitoring_configuration_s3_logging_configuration_kms_key TEXT,
    data_configuration_monitoring_configuration_s3_logging_configuration_log_location TEXT,
    data_configuration_publish_cloud_watch_metrics_enabled BOOLEAN,
    data_configuration_query_results_s3_access_grants_configuration_present BOOLEAN NOT NULL,
    data_configuration_query_results_s3_access_grants_configuration_authentication_type TEXT,
    data_configuration_query_results_s3_access_grants_configuration_create_user_level_prefix BOOLEAN,
    data_configuration_query_results_s3_access_grants_configuration_enable_s3_access_grants BOOLEAN,
    data_configuration_requester_pays_enabled BOOLEAN,
    data_configuration_result_configuration_present BOOLEAN NOT NULL,
    data_configuration_result_configuration_acl_configuration_present BOOLEAN NOT NULL,
    data_configuration_result_configuration_acl_configuration_s3_acl_option TEXT,
    data_configuration_result_configuration_encryption_configuration_present BOOLEAN NOT NULL,
    data_configuration_result_configuration_encryption_configuration_encryption_option TEXT,
    data_configuration_result_configuration_encryption_configuration_kms_key TEXT,
    data_configuration_result_configuration_expected_bucket_owner TEXT,
    data_configuration_result_configuration_output_location TEXT,
    data_creation_time DATETIME,
    data_description TEXT,
    data_identity_center_application_arn TEXT,
    data_name TEXT,
    data_state TEXT,
    tags_present BOOLEAN NOT NULL,
    UNIQUE (key_scope_partition, key_scope_account_id, key_scope_region, key_name)
);

CREATE TABLE athena_work_groups_data_configuration_engine_configuration_additional_configs (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_work_groups_data_configuration_engine_configuration_classifications (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value_name TEXT,
    value_properties_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_work_groups_data_configuration_engine_configuration_classifications_value_properties (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups_data_configuration_engine_configuration_classifications(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_work_groups_data_configuration_engine_configuration_spark_properties (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value_present BOOLEAN NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_value (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, position)
);

CREATE TABLE athena_work_groups_tags (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_work_groups(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_catalogs (
    id INTEGER PRIMARY KEY,
    key_scope_partition TEXT NOT NULL,
    key_scope_account_id TEXT NOT NULL,
    key_scope_region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    data_connection_type TEXT,
    data_description TEXT,
    data_error TEXT,
    data_name TEXT,
    data_parameters_present BOOLEAN NOT NULL,
    data_status TEXT,
    data_type TEXT,
    tags_present BOOLEAN NOT NULL,
    UNIQUE (key_scope_partition, key_scope_account_id, key_scope_region, key_name)
);

CREATE TABLE athena_catalogs_data_parameters (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_catalogs(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_catalogs_tags (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES athena_catalogs(id) ON DELETE CASCADE,
    map_key TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (parent_id, map_key)
);

CREATE TABLE athena_named_queries (
    id INTEGER PRIMARY KEY,
    key_scope_partition TEXT NOT NULL,
    key_scope_account_id TEXT NOT NULL,
    key_scope_region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    data_database TEXT,
    data_description TEXT,
    data_name TEXT,
    data_named_query_id TEXT,
    data_query_string TEXT,
    data_work_group TEXT,
    token TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    UNIQUE (key_scope_partition, key_scope_account_id, key_scope_region, key_name)
);
CREATE UNIQUE INDEX athena_named_queries_token ON athena_named_queries(key_scope_partition, key_scope_account_id, key_scope_region, token) WHERE token <> '';

CREATE TABLE athena_prepared_statements (
    id INTEGER PRIMARY KEY,
    key_work_group_scope_partition TEXT NOT NULL,
    key_work_group_scope_account_id TEXT NOT NULL,
    key_work_group_scope_region TEXT NOT NULL,
    key_work_group_name TEXT NOT NULL,
    key_name TEXT NOT NULL,
    data_description TEXT,
    data_last_modified_time DATETIME,
    data_query_statement TEXT,
    data_statement_name TEXT,
    data_work_group_name TEXT,
    UNIQUE (key_work_group_scope_partition, key_work_group_scope_account_id, key_work_group_scope_region, key_work_group_name, key_name)
);

