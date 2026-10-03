-- name: GetProject :one
SELECT * FROM codebuild_projects WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ?;
-- name: ListProjects :many
SELECT * FROM codebuild_projects WHERE partition = ? AND account_id = ? AND region = ? ORDER BY project_name;
-- name: DeleteProject :exec
DELETE FROM codebuild_projects WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ?;
-- name: PutProject :exec
INSERT INTO codebuild_projects (
 partition, account_id, region, project_name, build_number, arn, name, auto_retry_limit, concurrent_build_limit, created,
 description, encryption_key, last_modified, project_visibility, public_project_alias, queued_timeout_in_minutes,
 resource_access_role, service_role, source_version, timeout_in_minutes, artifacts, badge, build_batch_config, cache,
 environment, file_system_locations, logs_config, secondary_artifacts, secondary_sources, source, vpc_config, webhook,
 environment_variables_present, secondary_source_versions_present, tags_present
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, project_name) DO UPDATE SET
 build_number = excluded.build_number, arn = excluded.arn, name = excluded.name, auto_retry_limit = excluded.auto_retry_limit,
 concurrent_build_limit = excluded.concurrent_build_limit, created = excluded.created, description = excluded.description,
 encryption_key = excluded.encryption_key, last_modified = excluded.last_modified, project_visibility = excluded.project_visibility,
 public_project_alias = excluded.public_project_alias, queued_timeout_in_minutes = excluded.queued_timeout_in_minutes,
 resource_access_role = excluded.resource_access_role, service_role = excluded.service_role, source_version = excluded.source_version,
 timeout_in_minutes = excluded.timeout_in_minutes, artifacts = excluded.artifacts, badge = excluded.badge,
 build_batch_config = excluded.build_batch_config, cache = excluded.cache, environment = excluded.environment,
 file_system_locations = excluded.file_system_locations, logs_config = excluded.logs_config, secondary_artifacts = excluded.secondary_artifacts,
 secondary_sources = excluded.secondary_sources, source = excluded.source, vpc_config = excluded.vpc_config, webhook = excluded.webhook,
 environment_variables_present = excluded.environment_variables_present, secondary_source_versions_present = excluded.secondary_source_versions_present,
 tags_present = excluded.tags_present;

-- name: GetBuild :one
SELECT * FROM codebuild_builds WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: ListBuilds :many
SELECT * FROM codebuild_builds WHERE partition = ? AND account_id = ? AND region = ? ORDER BY resource_id;
-- name: ListActiveBuilds :many
SELECT * FROM codebuild_builds WHERE build_complete IS NULL OR build_complete = 0 OR delete_requested = 1 OR cleanup_pending = 1 ORDER BY partition, account_id, region, resource_id;
-- name: DeleteBuild :exec
DELETE FROM codebuild_builds WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuild :exec
INSERT INTO codebuild_builds (
 partition, account_id, region, resource_id, accepted_event_id, idempotency_token, request_hash, deadline, queued_deadline,
 delete_requested, cleanup_pending, credential_token,
 stop_requested, log_offset, failure, fleet_arn, arn, build_id, build_batch_arn, build_complete, build_number, build_status,
 current_phase, encryption_key, end_time, initiator, project_name, queued_timeout_in_minutes, resolved_source_version, service_role,
 source_version, start_time, timeout_in_minutes, artifacts_config, logs_config, artifacts, auto_retry_config, cache, debug_session,
 environment, file_system_locations, logs, network_interface, secondary_artifacts, secondary_sources, source, vpc_config,
 environment_variables_present, exported_environment_variables_present, phases_present, report_arns_present, secondary_source_versions_present,
 pipeline_action_id, secondary_artifacts_config, retry_source_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, sqlc.arg(retry_source_id))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET
 accepted_event_id = excluded.accepted_event_id, idempotency_token = excluded.idempotency_token, request_hash = excluded.request_hash,
 deadline = excluded.deadline, queued_deadline = excluded.queued_deadline, stop_requested = excluded.stop_requested,
 delete_requested = excluded.delete_requested, cleanup_pending = excluded.cleanup_pending, credential_token = excluded.credential_token,
 log_offset = excluded.log_offset, failure = excluded.failure, fleet_arn = excluded.fleet_arn, arn = excluded.arn, build_id = excluded.build_id,
 build_batch_arn = excluded.build_batch_arn, build_complete = excluded.build_complete, build_number = excluded.build_number,
 build_status = excluded.build_status, current_phase = excluded.current_phase, encryption_key = excluded.encryption_key, end_time = excluded.end_time,
 initiator = excluded.initiator, project_name = excluded.project_name, queued_timeout_in_minutes = excluded.queued_timeout_in_minutes,
 resolved_source_version = excluded.resolved_source_version, service_role = excluded.service_role, source_version = excluded.source_version,
 start_time = excluded.start_time, timeout_in_minutes = excluded.timeout_in_minutes, artifacts_config = excluded.artifacts_config,
 logs_config = excluded.logs_config, artifacts = excluded.artifacts, auto_retry_config = excluded.auto_retry_config, cache = excluded.cache,
 debug_session = excluded.debug_session, environment = excluded.environment, file_system_locations = excluded.file_system_locations,
 logs = excluded.logs, network_interface = excluded.network_interface, secondary_artifacts = excluded.secondary_artifacts,
 secondary_sources = excluded.secondary_sources, source = excluded.source, vpc_config = excluded.vpc_config,
 environment_variables_present = excluded.environment_variables_present,
 exported_environment_variables_present = excluded.exported_environment_variables_present, phases_present = excluded.phases_present,
 report_arns_present = excluded.report_arns_present, secondary_source_versions_present = excluded.secondary_source_versions_present,
 pipeline_action_id = excluded.pipeline_action_id, secondary_artifacts_config = excluded.secondary_artifacts_config,
 retry_source_id = excluded.retry_source_id;

-- name: GetFleet :one
SELECT * FROM codebuild_fleets WHERE partition = ? AND account_id = ? AND region = ? AND fleet_name = ?;
-- name: ListFleets :many
SELECT * FROM codebuild_fleets WHERE partition = ? AND account_id = ? AND region = ? ORDER BY fleet_name;
-- name: ListAllFleets :many
SELECT * FROM codebuild_fleets ORDER BY partition, account_id, region, fleet_name;
-- name: DeleteFleet :exec
DELETE FROM codebuild_fleets WHERE partition = ? AND account_id = ? AND region = ? AND fleet_name = ?;
-- name: PutFleet :exec
INSERT INTO codebuild_fleets (
 partition, account_id, region, fleet_name, arn, name, fleet_id, base_capacity, compute_type, created, environment_type,
 fleet_service_role, image_id, last_modified, overflow_behavior, compute_configuration, proxy_configuration,
 scaling_configuration, status, vpc_config, tags_present
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, fleet_name) DO UPDATE SET
 arn = excluded.arn, name = excluded.name, fleet_id = excluded.fleet_id, base_capacity = excluded.base_capacity,
 compute_type = excluded.compute_type, created = excluded.created, environment_type = excluded.environment_type,
 fleet_service_role = excluded.fleet_service_role, image_id = excluded.image_id, last_modified = excluded.last_modified,
 overflow_behavior = excluded.overflow_behavior, compute_configuration = excluded.compute_configuration,
 proxy_configuration = excluded.proxy_configuration, scaling_configuration = excluded.scaling_configuration,
 status = excluded.status, vpc_config = excluded.vpc_config, tags_present = excluded.tags_present;

-- name: GetCredential :one
SELECT * FROM codebuild_credentials WHERE partition = ? AND account_id = ? AND region = ? AND server_type = ? AND auth_type = ?;
-- name: ListCredentials :many
SELECT * FROM codebuild_credentials WHERE partition = ? AND account_id = ? AND region = ? ORDER BY server_type, auth_type;
-- name: DeleteCredential :exec
DELETE FROM codebuild_credentials WHERE partition = ? AND account_id = ? AND region = ? AND server_type = ? AND auth_type = ?;
-- name: PutCredential :exec
INSERT INTO codebuild_credentials (partition, account_id, region, server_type, auth_type, arn, ciphertext) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, server_type, auth_type) DO UPDATE SET arn = excluded.arn, ciphertext = excluded.ciphertext;

-- name: ListProjectTags :many
SELECT * FROM codebuild_project_tags WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ? ORDER BY position;
-- name: DeleteProjectTags :exec
DELETE FROM codebuild_project_tags WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ?;
-- name: PutProjectTag :exec
INSERT INTO codebuild_project_tags (partition, account_id, region, project_name, position, tag_key, tag_value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListFleetTags :many
SELECT * FROM codebuild_fleet_tags WHERE partition = ? AND account_id = ? AND region = ? AND fleet_name = ? ORDER BY position;
-- name: DeleteFleetTags :exec
DELETE FROM codebuild_fleet_tags WHERE partition = ? AND account_id = ? AND region = ? AND fleet_name = ?;
-- name: PutFleetTag :exec
INSERT INTO codebuild_fleet_tags (partition, account_id, region, fleet_name, position, tag_key, tag_value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListProjectVariables :many
SELECT * FROM codebuild_project_variables WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ? ORDER BY position;
-- name: DeleteProjectVariables :exec
DELETE FROM codebuild_project_variables WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ?;
-- name: PutProjectVariable :exec
INSERT INTO codebuild_project_variables (partition, account_id, region, project_name, position, name, value, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListBuildVariables :many
SELECT * FROM codebuild_build_variables WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeleteBuildVariables :exec
DELETE FROM codebuild_build_variables WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuildVariable :exec
INSERT INTO codebuild_build_variables (partition, account_id, region, resource_id, position, name, value, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListProjectSourceVersions :many
SELECT * FROM codebuild_project_source_versions WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ? ORDER BY position;
-- name: DeleteProjectSourceVersions :exec
DELETE FROM codebuild_project_source_versions WHERE partition = ? AND account_id = ? AND region = ? AND project_name = ?;
-- name: PutProjectSourceVersion :exec
INSERT INTO codebuild_project_source_versions (partition, account_id, region, project_name, position, source_identifier, source_version) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListBuildSourceVersions :many
SELECT * FROM codebuild_build_source_versions WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeleteBuildSourceVersions :exec
DELETE FROM codebuild_build_source_versions WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuildSourceVersion :exec
INSERT INTO codebuild_build_source_versions (partition, account_id, region, resource_id, position, source_identifier, source_version) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListBuildExportedVariables :many
SELECT * FROM codebuild_build_exported_variables WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeleteBuildExportedVariables :exec
DELETE FROM codebuild_build_exported_variables WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuildExportedVariable :exec
INSERT INTO codebuild_build_exported_variables (partition, account_id, region, resource_id, position, name, value) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListBuildReportARNs :many
SELECT * FROM codebuild_build_report_arns WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeleteBuildReportARNs :exec
DELETE FROM codebuild_build_report_arns WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuildReportARN :exec
INSERT INTO codebuild_build_report_arns (partition, account_id, region, resource_id, position, arn) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListBuildPhases :many
SELECT * FROM codebuild_build_phases WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeleteBuildPhases :exec
DELETE FROM codebuild_build_phases WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutBuildPhase :exec
INSERT INTO codebuild_build_phases (partition, account_id, region, resource_id, position, duration_in_seconds, end_time, phase_status, phase_type, start_time, contexts_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListBuildPhaseContexts :many
SELECT * FROM codebuild_build_phase_contexts WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND phase_position = ? ORDER BY position;
-- name: PutBuildPhaseContext :exec
INSERT INTO codebuild_build_phase_contexts (partition, account_id, region, resource_id, phase_position, position, message, status_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListPipelineInputs :many
SELECT * FROM codebuild_pipeline_inputs WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeletePipelineInputs :exec
DELETE FROM codebuild_pipeline_inputs WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutPipelineInput :exec
INSERT INTO codebuild_pipeline_inputs (partition, account_id, region, resource_id, position, artifact_name, location, version_id, revision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListPipelineOutputs :many
SELECT * FROM codebuild_pipeline_outputs WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;
-- name: DeletePipelineOutputs :exec
DELETE FROM codebuild_pipeline_outputs WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;
-- name: PutPipelineOutput :exec
INSERT INTO codebuild_pipeline_outputs (partition, account_id, region, resource_id, position, artifact_name, location, encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
