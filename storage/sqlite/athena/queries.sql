-- name: PutWorkGroup :one
INSERT INTO athena_work_groups (
    key_scope_partition,
    key_scope_account_id,
    key_scope_region,
    key_name,
    data_configuration_present,
    data_configuration_additional_configuration,
    data_configuration_bytes_scanned_cutoff_per_query,
    data_configuration_customer_content_encryption_configuration_present,
    data_configuration_customer_content_encryption_configuration_kms_key,
    data_configuration_enable_minimum_encryption_configuration,
    data_configuration_enforce_work_group_configuration,
    data_configuration_engine_configuration_present,
    data_configuration_engine_configuration_additional_configs_present,
    data_configuration_engine_configuration_classifications_present,
    data_configuration_engine_configuration_coordinator_dpu_size,
    data_configuration_engine_configuration_default_executor_dpu_size,
    data_configuration_engine_configuration_max_concurrent_dpus,
    data_configuration_engine_configuration_spark_properties_present,
    data_configuration_engine_version_present,
    data_configuration_engine_version_effective_engine_version,
    data_configuration_engine_version_selected_engine_version,
    data_configuration_execution_role,
    data_configuration_identity_center_configuration_present,
    data_configuration_identity_center_configuration_enable_identity_center,
    data_configuration_identity_center_configuration_identity_center_instance_arn,
    data_configuration_managed_query_results_configuration_present,
    data_configuration_managed_query_results_configuration_enabled,
    data_configuration_managed_query_results_configuration_encryption_configuration_present,
    data_configuration_managed_query_results_configuration_encryption_configuration_kms_key,
    data_configuration_monitoring_configuration_present,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_present,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_enabled,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_group,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_stream_name_prefix,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_present,
    data_configuration_monitoring_configuration_managed_logging_configuration_present,
    data_configuration_monitoring_configuration_managed_logging_configuration_enabled,
    data_configuration_monitoring_configuration_managed_logging_configuration_kms_key,
    data_configuration_monitoring_configuration_s3_logging_configuration_present,
    data_configuration_monitoring_configuration_s3_logging_configuration_enabled,
    data_configuration_monitoring_configuration_s3_logging_configuration_kms_key,
    data_configuration_monitoring_configuration_s3_logging_configuration_log_location,
    data_configuration_publish_cloud_watch_metrics_enabled,
    data_configuration_query_results_s3_access_grants_configuration_present,
    data_configuration_query_results_s3_access_grants_configuration_authentication_type,
    data_configuration_query_results_s3_access_grants_configuration_create_user_level_prefix,
    data_configuration_query_results_s3_access_grants_configuration_enable_s3_access_grants,
    data_configuration_requester_pays_enabled,
    data_configuration_result_configuration_present,
    data_configuration_result_configuration_acl_configuration_present,
    data_configuration_result_configuration_acl_configuration_s3_acl_option,
    data_configuration_result_configuration_encryption_configuration_present,
    data_configuration_result_configuration_encryption_configuration_encryption_option,
    data_configuration_result_configuration_encryption_configuration_kms_key,
    data_configuration_result_configuration_expected_bucket_owner,
    data_configuration_result_configuration_output_location,
    data_creation_time,
    data_description,
    data_identity_center_application_arn,
    data_name,
    data_state,
    tags_present
) VALUES (
    sqlc.arg(key_scope_partition),
    sqlc.arg(key_scope_account_id),
    sqlc.arg(key_scope_region),
    sqlc.arg(key_name),
    sqlc.arg(data_configuration_present),
    sqlc.arg(data_configuration_additional_configuration),
    sqlc.arg(data_configuration_bytes_scanned_cutoff_per_query),
    sqlc.arg(data_configuration_customer_content_encryption_configuration_present),
    sqlc.arg(data_configuration_customer_content_encryption_configuration_kms_key),
    sqlc.arg(data_configuration_enable_minimum_encryption_configuration),
    sqlc.arg(data_configuration_enforce_work_group_configuration),
    sqlc.arg(data_configuration_engine_configuration_present),
    sqlc.arg(data_configuration_engine_configuration_additional_configs_present),
    sqlc.arg(data_configuration_engine_configuration_classifications_present),
    sqlc.arg(data_configuration_engine_configuration_coordinator_dpu_size),
    sqlc.arg(data_configuration_engine_configuration_default_executor_dpu_size),
    sqlc.arg(data_configuration_engine_configuration_max_concurrent_dpus),
    sqlc.arg(data_configuration_engine_configuration_spark_properties_present),
    sqlc.arg(data_configuration_engine_version_present),
    sqlc.arg(data_configuration_engine_version_effective_engine_version),
    sqlc.arg(data_configuration_engine_version_selected_engine_version),
    sqlc.arg(data_configuration_execution_role),
    sqlc.arg(data_configuration_identity_center_configuration_present),
    sqlc.arg(data_configuration_identity_center_configuration_enable_identity_center),
    sqlc.arg(data_configuration_identity_center_configuration_identity_center_instance_arn),
    sqlc.arg(data_configuration_managed_query_results_configuration_present),
    sqlc.arg(data_configuration_managed_query_results_configuration_enabled),
    sqlc.arg(data_configuration_managed_query_results_configuration_encryption_configuration_present),
    sqlc.arg(data_configuration_managed_query_results_configuration_encryption_configuration_kms_key),
    sqlc.arg(data_configuration_monitoring_configuration_present),
    sqlc.arg(data_configuration_monitoring_configuration_cloud_watch_logging_configuration_present),
    sqlc.arg(data_configuration_monitoring_configuration_cloud_watch_logging_configuration_enabled),
    sqlc.arg(data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_group),
    sqlc.arg(data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_stream_name_prefix),
    sqlc.arg(data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_present),
    sqlc.arg(data_configuration_monitoring_configuration_managed_logging_configuration_present),
    sqlc.arg(data_configuration_monitoring_configuration_managed_logging_configuration_enabled),
    sqlc.arg(data_configuration_monitoring_configuration_managed_logging_configuration_kms_key),
    sqlc.arg(data_configuration_monitoring_configuration_s3_logging_configuration_present),
    sqlc.arg(data_configuration_monitoring_configuration_s3_logging_configuration_enabled),
    sqlc.arg(data_configuration_monitoring_configuration_s3_logging_configuration_kms_key),
    sqlc.arg(data_configuration_monitoring_configuration_s3_logging_configuration_log_location),
    sqlc.arg(data_configuration_publish_cloud_watch_metrics_enabled),
    sqlc.arg(data_configuration_query_results_s3_access_grants_configuration_present),
    sqlc.arg(data_configuration_query_results_s3_access_grants_configuration_authentication_type),
    sqlc.arg(data_configuration_query_results_s3_access_grants_configuration_create_user_level_prefix),
    sqlc.arg(data_configuration_query_results_s3_access_grants_configuration_enable_s3_access_grants),
    sqlc.arg(data_configuration_requester_pays_enabled),
    sqlc.arg(data_configuration_result_configuration_present),
    sqlc.arg(data_configuration_result_configuration_acl_configuration_present),
    sqlc.arg(data_configuration_result_configuration_acl_configuration_s3_acl_option),
    sqlc.arg(data_configuration_result_configuration_encryption_configuration_present),
    sqlc.arg(data_configuration_result_configuration_encryption_configuration_encryption_option),
    sqlc.arg(data_configuration_result_configuration_encryption_configuration_kms_key),
    sqlc.arg(data_configuration_result_configuration_expected_bucket_owner),
    sqlc.arg(data_configuration_result_configuration_output_location),
    sqlc.arg(data_creation_time),
    sqlc.arg(data_description),
    sqlc.arg(data_identity_center_application_arn),
    sqlc.arg(data_name),
    sqlc.arg(data_state),
    sqlc.arg(tags_present)
) ON CONFLICT (key_scope_partition, key_scope_account_id, key_scope_region, key_name) DO UPDATE SET
    data_configuration_present = excluded.data_configuration_present,
    data_configuration_additional_configuration = excluded.data_configuration_additional_configuration,
    data_configuration_bytes_scanned_cutoff_per_query = excluded.data_configuration_bytes_scanned_cutoff_per_query,
    data_configuration_customer_content_encryption_configuration_present = excluded.data_configuration_customer_content_encryption_configuration_present,
    data_configuration_customer_content_encryption_configuration_kms_key = excluded.data_configuration_customer_content_encryption_configuration_kms_key,
    data_configuration_enable_minimum_encryption_configuration = excluded.data_configuration_enable_minimum_encryption_configuration,
    data_configuration_enforce_work_group_configuration = excluded.data_configuration_enforce_work_group_configuration,
    data_configuration_engine_configuration_present = excluded.data_configuration_engine_configuration_present,
    data_configuration_engine_configuration_additional_configs_present = excluded.data_configuration_engine_configuration_additional_configs_present,
    data_configuration_engine_configuration_classifications_present = excluded.data_configuration_engine_configuration_classifications_present,
    data_configuration_engine_configuration_coordinator_dpu_size = excluded.data_configuration_engine_configuration_coordinator_dpu_size,
    data_configuration_engine_configuration_default_executor_dpu_size = excluded.data_configuration_engine_configuration_default_executor_dpu_size,
    data_configuration_engine_configuration_max_concurrent_dpus = excluded.data_configuration_engine_configuration_max_concurrent_dpus,
    data_configuration_engine_configuration_spark_properties_present = excluded.data_configuration_engine_configuration_spark_properties_present,
    data_configuration_engine_version_present = excluded.data_configuration_engine_version_present,
    data_configuration_engine_version_effective_engine_version = excluded.data_configuration_engine_version_effective_engine_version,
    data_configuration_engine_version_selected_engine_version = excluded.data_configuration_engine_version_selected_engine_version,
    data_configuration_execution_role = excluded.data_configuration_execution_role,
    data_configuration_identity_center_configuration_present = excluded.data_configuration_identity_center_configuration_present,
    data_configuration_identity_center_configuration_enable_identity_center = excluded.data_configuration_identity_center_configuration_enable_identity_center,
    data_configuration_identity_center_configuration_identity_center_instance_arn = excluded.data_configuration_identity_center_configuration_identity_center_instance_arn,
    data_configuration_managed_query_results_configuration_present = excluded.data_configuration_managed_query_results_configuration_present,
    data_configuration_managed_query_results_configuration_enabled = excluded.data_configuration_managed_query_results_configuration_enabled,
    data_configuration_managed_query_results_configuration_encryption_configuration_present = excluded.data_configuration_managed_query_results_configuration_encryption_configuration_present,
    data_configuration_managed_query_results_configuration_encryption_configuration_kms_key = excluded.data_configuration_managed_query_results_configuration_encryption_configuration_kms_key,
    data_configuration_monitoring_configuration_present = excluded.data_configuration_monitoring_configuration_present,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_present = excluded.data_configuration_monitoring_configuration_cloud_watch_logging_configuration_present,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_enabled = excluded.data_configuration_monitoring_configuration_cloud_watch_logging_configuration_enabled,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_group = excluded.data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_group,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_stream_name_prefix = excluded.data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_stream_name_prefix,
    data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_present = excluded.data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_present,
    data_configuration_monitoring_configuration_managed_logging_configuration_present = excluded.data_configuration_monitoring_configuration_managed_logging_configuration_present,
    data_configuration_monitoring_configuration_managed_logging_configuration_enabled = excluded.data_configuration_monitoring_configuration_managed_logging_configuration_enabled,
    data_configuration_monitoring_configuration_managed_logging_configuration_kms_key = excluded.data_configuration_monitoring_configuration_managed_logging_configuration_kms_key,
    data_configuration_monitoring_configuration_s3_logging_configuration_present = excluded.data_configuration_monitoring_configuration_s3_logging_configuration_present,
    data_configuration_monitoring_configuration_s3_logging_configuration_enabled = excluded.data_configuration_monitoring_configuration_s3_logging_configuration_enabled,
    data_configuration_monitoring_configuration_s3_logging_configuration_kms_key = excluded.data_configuration_monitoring_configuration_s3_logging_configuration_kms_key,
    data_configuration_monitoring_configuration_s3_logging_configuration_log_location = excluded.data_configuration_monitoring_configuration_s3_logging_configuration_log_location,
    data_configuration_publish_cloud_watch_metrics_enabled = excluded.data_configuration_publish_cloud_watch_metrics_enabled,
    data_configuration_query_results_s3_access_grants_configuration_present = excluded.data_configuration_query_results_s3_access_grants_configuration_present,
    data_configuration_query_results_s3_access_grants_configuration_authentication_type = excluded.data_configuration_query_results_s3_access_grants_configuration_authentication_type,
    data_configuration_query_results_s3_access_grants_configuration_create_user_level_prefix = excluded.data_configuration_query_results_s3_access_grants_configuration_create_user_level_prefix,
    data_configuration_query_results_s3_access_grants_configuration_enable_s3_access_grants = excluded.data_configuration_query_results_s3_access_grants_configuration_enable_s3_access_grants,
    data_configuration_requester_pays_enabled = excluded.data_configuration_requester_pays_enabled,
    data_configuration_result_configuration_present = excluded.data_configuration_result_configuration_present,
    data_configuration_result_configuration_acl_configuration_present = excluded.data_configuration_result_configuration_acl_configuration_present,
    data_configuration_result_configuration_acl_configuration_s3_acl_option = excluded.data_configuration_result_configuration_acl_configuration_s3_acl_option,
    data_configuration_result_configuration_encryption_configuration_present = excluded.data_configuration_result_configuration_encryption_configuration_present,
    data_configuration_result_configuration_encryption_configuration_encryption_option = excluded.data_configuration_result_configuration_encryption_configuration_encryption_option,
    data_configuration_result_configuration_encryption_configuration_kms_key = excluded.data_configuration_result_configuration_encryption_configuration_kms_key,
    data_configuration_result_configuration_expected_bucket_owner = excluded.data_configuration_result_configuration_expected_bucket_owner,
    data_configuration_result_configuration_output_location = excluded.data_configuration_result_configuration_output_location,
    data_creation_time = excluded.data_creation_time,
    data_description = excluded.data_description,
    data_identity_center_application_arn = excluded.data_identity_center_application_arn,
    data_name = excluded.data_name,
    data_state = excluded.data_state,
    tags_present = excluded.tags_present
RETURNING id;

-- name: GetWorkGroup :one
SELECT * FROM athena_work_groups WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: DeleteWorkGroup :exec
DELETE FROM athena_work_groups WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: ListWorkGroups :many
SELECT * FROM athena_work_groups WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND key_name > sqlc.arg(after_name) ORDER BY key_name LIMIT sqlc.arg(row_limit);

-- name: PutWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs :exec
INSERT INTO athena_work_groups_data_configuration_engine_configuration_additional_configs (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs :many
SELECT * FROM athena_work_groups_data_configuration_engine_configuration_additional_configs WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteWorkGroupDataConfigurationEngineConfigurationAdditionalConfigs :exec
DELETE FROM athena_work_groups_data_configuration_engine_configuration_additional_configs WHERE parent_id = ?;

-- name: PutWorkGroupDataConfigurationEngineConfigurationClassifications :one
INSERT INTO athena_work_groups_data_configuration_engine_configuration_classifications (
    parent_id,
    position,
    value_name,
    value_properties_present
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value_name),
    sqlc.arg(value_properties_present)
)
RETURNING id;

-- name: ListWorkGroupDataConfigurationEngineConfigurationClassifications :many
SELECT * FROM athena_work_groups_data_configuration_engine_configuration_classifications WHERE parent_id = ? ORDER BY position;

-- name: DeleteWorkGroupDataConfigurationEngineConfigurationClassifications :exec
DELETE FROM athena_work_groups_data_configuration_engine_configuration_classifications WHERE parent_id = ?;

-- name: PutWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties :exec
INSERT INTO athena_work_groups_data_configuration_engine_configuration_classifications_value_properties (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties :many
SELECT * FROM athena_work_groups_data_configuration_engine_configuration_classifications_value_properties WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteWorkGroupDataConfigurationEngineConfigurationClassificationsValueProperties :exec
DELETE FROM athena_work_groups_data_configuration_engine_configuration_classifications_value_properties WHERE parent_id = ?;

-- name: PutWorkGroupDataConfigurationEngineConfigurationSparkProperties :exec
INSERT INTO athena_work_groups_data_configuration_engine_configuration_spark_properties (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListWorkGroupDataConfigurationEngineConfigurationSparkProperties :many
SELECT * FROM athena_work_groups_data_configuration_engine_configuration_spark_properties WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteWorkGroupDataConfigurationEngineConfigurationSparkProperties :exec
DELETE FROM athena_work_groups_data_configuration_engine_configuration_spark_properties WHERE parent_id = ?;

-- name: PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes :one
INSERT INTO athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types (
    parent_id,
    map_key,
    value_present
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value_present)
)
RETURNING id;

-- name: ListWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes :many
SELECT * FROM athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypes :exec
DELETE FROM athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types WHERE parent_id = ?;

-- name: PutWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue :exec
INSERT INTO athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_value (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue :many
SELECT * FROM athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_value WHERE parent_id = ? ORDER BY position;

-- name: DeleteWorkGroupDataConfigurationMonitoringConfigurationCloudWatchLoggingConfigurationLogTypesValue :exec
DELETE FROM athena_work_groups_data_configuration_monitoring_configuration_cloud_watch_logging_configuration_log_types_value WHERE parent_id = ?;

-- name: PutWorkGroupTags :exec
INSERT INTO athena_work_groups_tags (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListWorkGroupTags :many
SELECT * FROM athena_work_groups_tags WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteWorkGroupTags :exec
DELETE FROM athena_work_groups_tags WHERE parent_id = ?;

-- name: PutCatalog :one
INSERT INTO athena_catalogs (
    key_scope_partition,
    key_scope_account_id,
    key_scope_region,
    key_name,
    data_connection_type,
    data_description,
    data_error,
    data_name,
    data_parameters_present,
    data_status,
    data_type,
    tags_present
) VALUES (
    sqlc.arg(key_scope_partition),
    sqlc.arg(key_scope_account_id),
    sqlc.arg(key_scope_region),
    sqlc.arg(key_name),
    sqlc.arg(data_connection_type),
    sqlc.arg(data_description),
    sqlc.arg(data_error),
    sqlc.arg(data_name),
    sqlc.arg(data_parameters_present),
    sqlc.arg(data_status),
    sqlc.arg(data_type),
    sqlc.arg(tags_present)
) ON CONFLICT (key_scope_partition, key_scope_account_id, key_scope_region, key_name) DO UPDATE SET
    data_connection_type = excluded.data_connection_type,
    data_description = excluded.data_description,
    data_error = excluded.data_error,
    data_name = excluded.data_name,
    data_parameters_present = excluded.data_parameters_present,
    data_status = excluded.data_status,
    data_type = excluded.data_type,
    tags_present = excluded.tags_present
RETURNING id;

-- name: GetCatalog :one
SELECT * FROM athena_catalogs WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: DeleteCatalog :exec
DELETE FROM athena_catalogs WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: ListCatalogs :many
SELECT * FROM athena_catalogs WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND key_name > sqlc.arg(after_name) ORDER BY key_name LIMIT sqlc.arg(row_limit);

-- name: PutCatalogDataParameters :exec
INSERT INTO athena_catalogs_data_parameters (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListCatalogDataParameters :many
SELECT * FROM athena_catalogs_data_parameters WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteCatalogDataParameters :exec
DELETE FROM athena_catalogs_data_parameters WHERE parent_id = ?;

-- name: PutCatalogTags :exec
INSERT INTO athena_catalogs_tags (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListCatalogTags :many
SELECT * FROM athena_catalogs_tags WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteCatalogTags :exec
DELETE FROM athena_catalogs_tags WHERE parent_id = ?;

-- name: PutNamedQuery :exec
INSERT INTO athena_named_queries (
    key_scope_partition,
    key_scope_account_id,
    key_scope_region,
    key_name,
    data_database,
    data_description,
    data_name,
    data_named_query_id,
    data_query_string,
    data_work_group,
    token,
    fingerprint
) VALUES (
    sqlc.arg(key_scope_partition),
    sqlc.arg(key_scope_account_id),
    sqlc.arg(key_scope_region),
    sqlc.arg(key_name),
    sqlc.arg(data_database),
    sqlc.arg(data_description),
    sqlc.arg(data_name),
    sqlc.arg(data_named_query_id),
    sqlc.arg(data_query_string),
    sqlc.arg(data_work_group),
    sqlc.arg(token),
    sqlc.arg(fingerprint)
) ON CONFLICT (key_scope_partition, key_scope_account_id, key_scope_region, key_name) DO UPDATE SET
    data_database = excluded.data_database,
    data_description = excluded.data_description,
    data_name = excluded.data_name,
    data_named_query_id = excluded.data_named_query_id,
    data_query_string = excluded.data_query_string,
    data_work_group = excluded.data_work_group,
    token = excluded.token,
    fingerprint = excluded.fingerprint
;

-- name: GetNamedQuery :one
SELECT * FROM athena_named_queries WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: DeleteNamedQuery :exec
DELETE FROM athena_named_queries WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: ListNamedQuerys :many
SELECT * FROM athena_named_queries WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND key_name > sqlc.arg(after_name) AND (CAST(sqlc.arg(work_group) AS TEXT) = '' OR data_work_group = sqlc.arg(work_group)) ORDER BY key_name LIMIT sqlc.arg(row_limit);

-- name: GetNamedQueryByToken :one
SELECT * FROM athena_named_queries WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND token = sqlc.arg(token) AND token <> '';

-- name: PutPreparedStatement :exec
INSERT INTO athena_prepared_statements (
    key_work_group_scope_partition,
    key_work_group_scope_account_id,
    key_work_group_scope_region,
    key_work_group_name,
    key_name,
    data_description,
    data_last_modified_time,
    data_query_statement,
    data_statement_name,
    data_work_group_name
) VALUES (
    sqlc.arg(key_work_group_scope_partition),
    sqlc.arg(key_work_group_scope_account_id),
    sqlc.arg(key_work_group_scope_region),
    sqlc.arg(key_work_group_name),
    sqlc.arg(key_name),
    sqlc.arg(data_description),
    sqlc.arg(data_last_modified_time),
    sqlc.arg(data_query_statement),
    sqlc.arg(data_statement_name),
    sqlc.arg(data_work_group_name)
) ON CONFLICT (key_work_group_scope_partition, key_work_group_scope_account_id, key_work_group_scope_region, key_work_group_name, key_name) DO UPDATE SET
    data_description = excluded.data_description,
    data_last_modified_time = excluded.data_last_modified_time,
    data_query_statement = excluded.data_query_statement,
    data_statement_name = excluded.data_statement_name,
    data_work_group_name = excluded.data_work_group_name
;

-- name: GetPreparedStatement :one
SELECT * FROM athena_prepared_statements WHERE key_work_group_scope_partition = sqlc.arg(key_work_group_scope_partition) AND key_work_group_scope_account_id = sqlc.arg(key_work_group_scope_account_id) AND key_work_group_scope_region = sqlc.arg(key_work_group_scope_region) AND key_work_group_name = sqlc.arg(key_work_group_name) AND key_name = sqlc.arg(key_name);

-- name: DeletePreparedStatement :exec
DELETE FROM athena_prepared_statements WHERE key_work_group_scope_partition = sqlc.arg(key_work_group_scope_partition) AND key_work_group_scope_account_id = sqlc.arg(key_work_group_scope_account_id) AND key_work_group_scope_region = sqlc.arg(key_work_group_scope_region) AND key_work_group_name = sqlc.arg(key_work_group_name) AND key_name = sqlc.arg(key_name);

-- name: ListPreparedStatements :many
SELECT * FROM athena_prepared_statements WHERE key_work_group_scope_partition = sqlc.arg(partition) AND key_work_group_scope_account_id = sqlc.arg(account_id) AND key_work_group_scope_region = sqlc.arg(region) AND key_name > sqlc.arg(after_name) AND key_work_group_name = sqlc.arg(work_group) ORDER BY key_name LIMIT sqlc.arg(row_limit);

-- name: PutQuery :one
INSERT INTO athena_queries (
    key_scope_partition,
    key_scope_account_id,
    key_scope_region,
    key_name,
    data_engine_version_present,
    data_engine_version_effective_engine_version,
    data_engine_version_selected_engine_version,
    data_execution_parameters_present,
    data_managed_query_results_configuration_present,
    data_managed_query_results_configuration_enabled,
    data_managed_query_results_configuration_encryption_configuration_present,
    data_managed_query_results_configuration_encryption_configuration_kms_key,
    data_query,
    data_query_execution_context_present,
    data_query_execution_context_catalog,
    data_query_execution_context_database,
    data_query_execution_id,
    data_query_results_s3_access_grants_configuration_present,
    data_query_results_s3_access_grants_configuration_authentication_type,
    data_query_results_s3_access_grants_configuration_create_user_level_prefix,
    data_query_results_s3_access_grants_configuration_enable_s3_access_grants,
    data_result_configuration_present,
    data_result_configuration_acl_configuration_present,
    data_result_configuration_acl_configuration_s3_acl_option,
    data_result_configuration_encryption_configuration_present,
    data_result_configuration_encryption_configuration_encryption_option,
    data_result_configuration_encryption_configuration_kms_key,
    data_result_configuration_expected_bucket_owner,
    data_result_configuration_output_location,
    data_result_reuse_configuration_present,
    data_result_reuse_configuration_result_reuse_by_age_configuration_present,
    data_result_reuse_configuration_result_reuse_by_age_configuration_enabled,
    data_result_reuse_configuration_result_reuse_by_age_configuration_max_age_in_minutes,
    data_statement_type,
    data_statistics_present,
    data_statistics_data_manifest_location,
    data_statistics_data_scanned_in_bytes,
    data_statistics_dpu_count,
    data_statistics_engine_execution_time_in_millis,
    data_statistics_query_planning_time_in_millis,
    data_statistics_query_queue_time_in_millis,
    data_statistics_result_reuse_information_present,
    data_statistics_result_reuse_information_reused_previous_result,
    data_statistics_service_pre_processing_time_in_millis,
    data_statistics_service_processing_time_in_millis,
    data_statistics_total_execution_time_in_millis,
    data_status_present,
    data_status_athena_error_present,
    data_status_athena_error_error_category,
    data_status_athena_error_error_message,
    data_status_athena_error_error_type,
    data_status_athena_error_retryable,
    data_status_completion_date_time,
    data_status_state,
    data_status_state_change_reason,
    data_status_submission_date_time,
    data_substatement_type,
    data_work_group,
    token,
    fingerprint,
    caller_account_id,
    caller_region,
    caller_partition,
    caller_access_key_id,
    caller_request_id,
    caller_parent_event_id,
    caller_trace_header,
    caller_principal_arn,
    caller_principal_id,
    caller_user_name,
    caller_session_type,
    caller_issuer_arn,
    caller_issuer_id,
    caller_session_policies_present,
    caller_session_policy_ar_ns_present,
    caller_has_session_policy,
    caller_session_context_present,
    caller_federated_provider,
    caller_session_tags_present,
    caller_transitive_tag_keys_present,
    caller_source_identity,
    caller_mfa_present,
    caller_mfa_authenticated_at,
    caller_token_issue_time,
    caller_called_via_present,
    caller_transport_known,
    caller_source_ip,
    caller_secure_transport,
    caller_user_agent,
    caller_signature_version,
    caller_authentication_method,
    caller_service_principal_name,
    caller_service_principal_source_arn,
    caller_service_principal_type,
    caller_service_principal_aliases_present,
    caller_invoked_by,
    caller_in_scope_of_issuer_type,
    caller_in_scope_of_credentials_issued_to,
    parent_event_id,
    version,
    due,
    started,
    engine_id,
    columns_present,
    update_count,
    publish_metrics,
    requester_pays,
    bytes_cutoff
) VALUES (
    sqlc.arg(key_scope_partition),
    sqlc.arg(key_scope_account_id),
    sqlc.arg(key_scope_region),
    sqlc.arg(key_name),
    sqlc.arg(data_engine_version_present),
    sqlc.arg(data_engine_version_effective_engine_version),
    sqlc.arg(data_engine_version_selected_engine_version),
    sqlc.arg(data_execution_parameters_present),
    sqlc.arg(data_managed_query_results_configuration_present),
    sqlc.arg(data_managed_query_results_configuration_enabled),
    sqlc.arg(data_managed_query_results_configuration_encryption_configuration_present),
    sqlc.arg(data_managed_query_results_configuration_encryption_configuration_kms_key),
    sqlc.arg(data_query),
    sqlc.arg(data_query_execution_context_present),
    sqlc.arg(data_query_execution_context_catalog),
    sqlc.arg(data_query_execution_context_database),
    sqlc.arg(data_query_execution_id),
    sqlc.arg(data_query_results_s3_access_grants_configuration_present),
    sqlc.arg(data_query_results_s3_access_grants_configuration_authentication_type),
    sqlc.arg(data_query_results_s3_access_grants_configuration_create_user_level_prefix),
    sqlc.arg(data_query_results_s3_access_grants_configuration_enable_s3_access_grants),
    sqlc.arg(data_result_configuration_present),
    sqlc.arg(data_result_configuration_acl_configuration_present),
    sqlc.arg(data_result_configuration_acl_configuration_s3_acl_option),
    sqlc.arg(data_result_configuration_encryption_configuration_present),
    sqlc.arg(data_result_configuration_encryption_configuration_encryption_option),
    sqlc.arg(data_result_configuration_encryption_configuration_kms_key),
    sqlc.arg(data_result_configuration_expected_bucket_owner),
    sqlc.arg(data_result_configuration_output_location),
    sqlc.arg(data_result_reuse_configuration_present),
    sqlc.arg(data_result_reuse_configuration_result_reuse_by_age_configuration_present),
    sqlc.arg(data_result_reuse_configuration_result_reuse_by_age_configuration_enabled),
    sqlc.arg(data_result_reuse_configuration_result_reuse_by_age_configuration_max_age_in_minutes),
    sqlc.arg(data_statement_type),
    sqlc.arg(data_statistics_present),
    sqlc.arg(data_statistics_data_manifest_location),
    sqlc.arg(data_statistics_data_scanned_in_bytes),
    sqlc.arg(data_statistics_dpu_count),
    sqlc.arg(data_statistics_engine_execution_time_in_millis),
    sqlc.arg(data_statistics_query_planning_time_in_millis),
    sqlc.arg(data_statistics_query_queue_time_in_millis),
    sqlc.arg(data_statistics_result_reuse_information_present),
    sqlc.arg(data_statistics_result_reuse_information_reused_previous_result),
    sqlc.arg(data_statistics_service_pre_processing_time_in_millis),
    sqlc.arg(data_statistics_service_processing_time_in_millis),
    sqlc.arg(data_statistics_total_execution_time_in_millis),
    sqlc.arg(data_status_present),
    sqlc.arg(data_status_athena_error_present),
    sqlc.arg(data_status_athena_error_error_category),
    sqlc.arg(data_status_athena_error_error_message),
    sqlc.arg(data_status_athena_error_error_type),
    sqlc.arg(data_status_athena_error_retryable),
    sqlc.arg(data_status_completion_date_time),
    sqlc.arg(data_status_state),
    sqlc.arg(data_status_state_change_reason),
    sqlc.arg(data_status_submission_date_time),
    sqlc.arg(data_substatement_type),
    sqlc.arg(data_work_group),
    sqlc.arg(token),
    sqlc.arg(fingerprint),
    sqlc.arg(caller_account_id),
    sqlc.arg(caller_region),
    sqlc.arg(caller_partition),
    sqlc.arg(caller_access_key_id),
    sqlc.arg(caller_request_id),
    sqlc.arg(caller_parent_event_id),
    sqlc.arg(caller_trace_header),
    sqlc.arg(caller_principal_arn),
    sqlc.arg(caller_principal_id),
    sqlc.arg(caller_user_name),
    sqlc.arg(caller_session_type),
    sqlc.arg(caller_issuer_arn),
    sqlc.arg(caller_issuer_id),
    sqlc.arg(caller_session_policies_present),
    sqlc.arg(caller_session_policy_ar_ns_present),
    sqlc.arg(caller_has_session_policy),
    sqlc.arg(caller_session_context_present),
    sqlc.arg(caller_federated_provider),
    sqlc.arg(caller_session_tags_present),
    sqlc.arg(caller_transitive_tag_keys_present),
    sqlc.arg(caller_source_identity),
    sqlc.arg(caller_mfa_present),
    sqlc.arg(caller_mfa_authenticated_at),
    sqlc.arg(caller_token_issue_time),
    sqlc.arg(caller_called_via_present),
    sqlc.arg(caller_transport_known),
    sqlc.arg(caller_source_ip),
    sqlc.arg(caller_secure_transport),
    sqlc.arg(caller_user_agent),
    sqlc.arg(caller_signature_version),
    sqlc.arg(caller_authentication_method),
    sqlc.arg(caller_service_principal_name),
    sqlc.arg(caller_service_principal_source_arn),
    sqlc.arg(caller_service_principal_type),
    sqlc.arg(caller_service_principal_aliases_present),
    sqlc.arg(caller_invoked_by),
    sqlc.arg(caller_in_scope_of_issuer_type),
    sqlc.arg(caller_in_scope_of_credentials_issued_to),
    sqlc.arg(parent_event_id),
    sqlc.arg(version),
    sqlc.arg(due),
    sqlc.arg(started),
    sqlc.arg(engine_id),
    sqlc.arg(columns_present),
    sqlc.arg(update_count),
    sqlc.arg(publish_metrics),
    sqlc.arg(requester_pays),
    sqlc.arg(bytes_cutoff)
) ON CONFLICT (key_scope_partition, key_scope_account_id, key_scope_region, key_name) DO UPDATE SET
    data_engine_version_present = excluded.data_engine_version_present,
    data_engine_version_effective_engine_version = excluded.data_engine_version_effective_engine_version,
    data_engine_version_selected_engine_version = excluded.data_engine_version_selected_engine_version,
    data_execution_parameters_present = excluded.data_execution_parameters_present,
    data_managed_query_results_configuration_present = excluded.data_managed_query_results_configuration_present,
    data_managed_query_results_configuration_enabled = excluded.data_managed_query_results_configuration_enabled,
    data_managed_query_results_configuration_encryption_configuration_present = excluded.data_managed_query_results_configuration_encryption_configuration_present,
    data_managed_query_results_configuration_encryption_configuration_kms_key = excluded.data_managed_query_results_configuration_encryption_configuration_kms_key,
    data_query = excluded.data_query,
    data_query_execution_context_present = excluded.data_query_execution_context_present,
    data_query_execution_context_catalog = excluded.data_query_execution_context_catalog,
    data_query_execution_context_database = excluded.data_query_execution_context_database,
    data_query_execution_id = excluded.data_query_execution_id,
    data_query_results_s3_access_grants_configuration_present = excluded.data_query_results_s3_access_grants_configuration_present,
    data_query_results_s3_access_grants_configuration_authentication_type = excluded.data_query_results_s3_access_grants_configuration_authentication_type,
    data_query_results_s3_access_grants_configuration_create_user_level_prefix = excluded.data_query_results_s3_access_grants_configuration_create_user_level_prefix,
    data_query_results_s3_access_grants_configuration_enable_s3_access_grants = excluded.data_query_results_s3_access_grants_configuration_enable_s3_access_grants,
    data_result_configuration_present = excluded.data_result_configuration_present,
    data_result_configuration_acl_configuration_present = excluded.data_result_configuration_acl_configuration_present,
    data_result_configuration_acl_configuration_s3_acl_option = excluded.data_result_configuration_acl_configuration_s3_acl_option,
    data_result_configuration_encryption_configuration_present = excluded.data_result_configuration_encryption_configuration_present,
    data_result_configuration_encryption_configuration_encryption_option = excluded.data_result_configuration_encryption_configuration_encryption_option,
    data_result_configuration_encryption_configuration_kms_key = excluded.data_result_configuration_encryption_configuration_kms_key,
    data_result_configuration_expected_bucket_owner = excluded.data_result_configuration_expected_bucket_owner,
    data_result_configuration_output_location = excluded.data_result_configuration_output_location,
    data_result_reuse_configuration_present = excluded.data_result_reuse_configuration_present,
    data_result_reuse_configuration_result_reuse_by_age_configuration_present = excluded.data_result_reuse_configuration_result_reuse_by_age_configuration_present,
    data_result_reuse_configuration_result_reuse_by_age_configuration_enabled = excluded.data_result_reuse_configuration_result_reuse_by_age_configuration_enabled,
    data_result_reuse_configuration_result_reuse_by_age_configuration_max_age_in_minutes = excluded.data_result_reuse_configuration_result_reuse_by_age_configuration_max_age_in_minutes,
    data_statement_type = excluded.data_statement_type,
    data_statistics_present = excluded.data_statistics_present,
    data_statistics_data_manifest_location = excluded.data_statistics_data_manifest_location,
    data_statistics_data_scanned_in_bytes = excluded.data_statistics_data_scanned_in_bytes,
    data_statistics_dpu_count = excluded.data_statistics_dpu_count,
    data_statistics_engine_execution_time_in_millis = excluded.data_statistics_engine_execution_time_in_millis,
    data_statistics_query_planning_time_in_millis = excluded.data_statistics_query_planning_time_in_millis,
    data_statistics_query_queue_time_in_millis = excluded.data_statistics_query_queue_time_in_millis,
    data_statistics_result_reuse_information_present = excluded.data_statistics_result_reuse_information_present,
    data_statistics_result_reuse_information_reused_previous_result = excluded.data_statistics_result_reuse_information_reused_previous_result,
    data_statistics_service_pre_processing_time_in_millis = excluded.data_statistics_service_pre_processing_time_in_millis,
    data_statistics_service_processing_time_in_millis = excluded.data_statistics_service_processing_time_in_millis,
    data_statistics_total_execution_time_in_millis = excluded.data_statistics_total_execution_time_in_millis,
    data_status_present = excluded.data_status_present,
    data_status_athena_error_present = excluded.data_status_athena_error_present,
    data_status_athena_error_error_category = excluded.data_status_athena_error_error_category,
    data_status_athena_error_error_message = excluded.data_status_athena_error_error_message,
    data_status_athena_error_error_type = excluded.data_status_athena_error_error_type,
    data_status_athena_error_retryable = excluded.data_status_athena_error_retryable,
    data_status_completion_date_time = excluded.data_status_completion_date_time,
    data_status_state = excluded.data_status_state,
    data_status_state_change_reason = excluded.data_status_state_change_reason,
    data_status_submission_date_time = excluded.data_status_submission_date_time,
    data_substatement_type = excluded.data_substatement_type,
    data_work_group = excluded.data_work_group,
    token = excluded.token,
    fingerprint = excluded.fingerprint,
    caller_account_id = excluded.caller_account_id,
    caller_region = excluded.caller_region,
    caller_partition = excluded.caller_partition,
    caller_access_key_id = excluded.caller_access_key_id,
    caller_request_id = excluded.caller_request_id,
    caller_parent_event_id = excluded.caller_parent_event_id,
    caller_trace_header = excluded.caller_trace_header,
    caller_principal_arn = excluded.caller_principal_arn,
    caller_principal_id = excluded.caller_principal_id,
    caller_user_name = excluded.caller_user_name,
    caller_session_type = excluded.caller_session_type,
    caller_issuer_arn = excluded.caller_issuer_arn,
    caller_issuer_id = excluded.caller_issuer_id,
    caller_session_policies_present = excluded.caller_session_policies_present,
    caller_session_policy_ar_ns_present = excluded.caller_session_policy_ar_ns_present,
    caller_has_session_policy = excluded.caller_has_session_policy,
    caller_session_context_present = excluded.caller_session_context_present,
    caller_federated_provider = excluded.caller_federated_provider,
    caller_session_tags_present = excluded.caller_session_tags_present,
    caller_transitive_tag_keys_present = excluded.caller_transitive_tag_keys_present,
    caller_source_identity = excluded.caller_source_identity,
    caller_mfa_present = excluded.caller_mfa_present,
    caller_mfa_authenticated_at = excluded.caller_mfa_authenticated_at,
    caller_token_issue_time = excluded.caller_token_issue_time,
    caller_called_via_present = excluded.caller_called_via_present,
    caller_transport_known = excluded.caller_transport_known,
    caller_source_ip = excluded.caller_source_ip,
    caller_secure_transport = excluded.caller_secure_transport,
    caller_user_agent = excluded.caller_user_agent,
    caller_signature_version = excluded.caller_signature_version,
    caller_authentication_method = excluded.caller_authentication_method,
    caller_service_principal_name = excluded.caller_service_principal_name,
    caller_service_principal_source_arn = excluded.caller_service_principal_source_arn,
    caller_service_principal_type = excluded.caller_service_principal_type,
    caller_service_principal_aliases_present = excluded.caller_service_principal_aliases_present,
    caller_invoked_by = excluded.caller_invoked_by,
    caller_in_scope_of_issuer_type = excluded.caller_in_scope_of_issuer_type,
    caller_in_scope_of_credentials_issued_to = excluded.caller_in_scope_of_credentials_issued_to,
    parent_event_id = excluded.parent_event_id,
    version = excluded.version,
    due = excluded.due,
    started = excluded.started,
    engine_id = excluded.engine_id,
    columns_present = excluded.columns_present,
    update_count = excluded.update_count,
    publish_metrics = excluded.publish_metrics,
    requester_pays = excluded.requester_pays,
    bytes_cutoff = excluded.bytes_cutoff
RETURNING id;

-- name: GetQuery :one
SELECT * FROM athena_queries WHERE key_scope_partition = sqlc.arg(key_scope_partition) AND key_scope_account_id = sqlc.arg(key_scope_account_id) AND key_scope_region = sqlc.arg(key_scope_region) AND key_name = sqlc.arg(key_name);

-- name: DeleteWorkGroupQueries :exec
DELETE FROM athena_queries WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND data_work_group = CAST(sqlc.arg(work_group) AS TEXT);

-- name: ListQuerys :many
SELECT * FROM athena_queries WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND key_name > sqlc.arg(after_name) AND (CAST(sqlc.arg(work_group) AS TEXT) = '' OR data_work_group = sqlc.arg(work_group)) ORDER BY key_name LIMIT sqlc.arg(row_limit);

-- name: GetQueryByToken :one
SELECT * FROM athena_queries WHERE key_scope_partition = sqlc.arg(partition) AND key_scope_account_id = sqlc.arg(account_id) AND key_scope_region = sqlc.arg(region) AND token = sqlc.arg(token) AND token <> '';

-- name: NextQuery :one
SELECT * FROM athena_queries WHERE data_status_state = 'QUEUED' OR (data_status_state IN ('FAILED', 'CANCELLED') AND engine_id <> '') ORDER BY due, key_name, key_scope_partition, key_scope_account_id, key_scope_region LIMIT 1;

-- name: ActiveQueries :many
SELECT * FROM athena_queries WHERE data_status_state IN ('QUEUED', 'RUNNING') OR engine_id <> '' ORDER BY key_name, key_scope_partition, key_scope_account_id, key_scope_region;

-- name: PutQueryDataExecutionParameters :exec
INSERT INTO athena_queries_data_execution_parameters (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryDataExecutionParameters :many
SELECT * FROM athena_queries_data_execution_parameters WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryDataExecutionParameters :exec
DELETE FROM athena_queries_data_execution_parameters WHERE parent_id = ?;

-- name: PutQueryCallerSessionPolicies :exec
INSERT INTO athena_queries_caller_session_policies (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerSessionPolicies :many
SELECT * FROM athena_queries_caller_session_policies WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerSessionPolicies :exec
DELETE FROM athena_queries_caller_session_policies WHERE parent_id = ?;

-- name: PutQueryCallerSessionPolicyARNs :exec
INSERT INTO athena_queries_caller_session_policy_ar_ns (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerSessionPolicyARNs :many
SELECT * FROM athena_queries_caller_session_policy_ar_ns WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerSessionPolicyARNs :exec
DELETE FROM athena_queries_caller_session_policy_ar_ns WHERE parent_id = ?;

-- name: PutQueryCallerSessionContext :one
INSERT INTO athena_queries_caller_session_context (
    parent_id,
    map_key,
    value_present
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value_present)
)
RETURNING id;

-- name: ListQueryCallerSessionContext :many
SELECT * FROM athena_queries_caller_session_context WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteQueryCallerSessionContext :exec
DELETE FROM athena_queries_caller_session_context WHERE parent_id = ?;

-- name: PutQueryCallerSessionContextValue :exec
INSERT INTO athena_queries_caller_session_context_value (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerSessionContextValue :many
SELECT * FROM athena_queries_caller_session_context_value WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerSessionContextValue :exec
DELETE FROM athena_queries_caller_session_context_value WHERE parent_id = ?;

-- name: PutQueryCallerSessionTags :exec
INSERT INTO athena_queries_caller_session_tags (
    parent_id,
    map_key,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(map_key),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerSessionTags :many
SELECT * FROM athena_queries_caller_session_tags WHERE parent_id = ? ORDER BY map_key;

-- name: DeleteQueryCallerSessionTags :exec
DELETE FROM athena_queries_caller_session_tags WHERE parent_id = ?;

-- name: PutQueryCallerTransitiveTagKeys :exec
INSERT INTO athena_queries_caller_transitive_tag_keys (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerTransitiveTagKeys :many
SELECT * FROM athena_queries_caller_transitive_tag_keys WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerTransitiveTagKeys :exec
DELETE FROM athena_queries_caller_transitive_tag_keys WHERE parent_id = ?;

-- name: PutQueryCallerCalledVia :exec
INSERT INTO athena_queries_caller_called_via (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerCalledVia :many
SELECT * FROM athena_queries_caller_called_via WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerCalledVia :exec
DELETE FROM athena_queries_caller_called_via WHERE parent_id = ?;

-- name: PutQueryCallerServicePrincipalAliases :exec
INSERT INTO athena_queries_caller_service_principal_aliases (
    parent_id,
    position,
    value
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value)
)
;

-- name: ListQueryCallerServicePrincipalAliases :many
SELECT * FROM athena_queries_caller_service_principal_aliases WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryCallerServicePrincipalAliases :exec
DELETE FROM athena_queries_caller_service_principal_aliases WHERE parent_id = ?;

-- name: PutQueryColumns :exec
INSERT INTO athena_queries_columns (
    parent_id,
    position,
    value_case_sensitive,
    value_catalog_name,
    value_label,
    value_name,
    value_nullable,
    value_precision,
    value_scale,
    value_schema_name,
    value_table_name,
    value_type
) VALUES (
    sqlc.arg(parent_id),
    sqlc.arg(position),
    sqlc.arg(value_case_sensitive),
    sqlc.arg(value_catalog_name),
    sqlc.arg(value_label),
    sqlc.arg(value_name),
    sqlc.arg(value_nullable),
    sqlc.arg(value_precision),
    sqlc.arg(value_scale),
    sqlc.arg(value_schema_name),
    sqlc.arg(value_table_name),
    sqlc.arg(value_type)
)
;

-- name: ListQueryColumns :many
SELECT * FROM athena_queries_columns WHERE parent_id = ? ORDER BY position;

-- name: DeleteQueryColumns :exec
DELETE FROM athena_queries_columns WHERE parent_id = ?;

