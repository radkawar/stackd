-- name: PutApplication :exec
INSERT INTO appconfig_applications (partition, account_id, region, id, name, description)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET name=excluded.name, description=excluded.description;

-- name: ListApplications :many
SELECT * FROM appconfig_applications WHERE partition=? AND account_id=? AND region=? ORDER BY id;

-- name: DeleteApplication :exec
DELETE FROM appconfig_applications WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: PutEnvironment :one
INSERT INTO appconfig_environments (partition, account_id, region, application_id, id, name, description, state, last_poll, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, application_id, id) DO UPDATE SET name=excluded.name, description=excluded.description, state=excluded.state, last_poll=excluded.last_poll, created_at=excluded.created_at
RETURNING row_id;

-- name: ListEnvironments :many
SELECT * FROM appconfig_environments WHERE partition=? AND account_id=? AND region=? AND application_id=? ORDER BY application_id, id;

-- name: DeleteEnvironment :exec
DELETE FROM appconfig_environments WHERE partition=? AND account_id=? AND region=? AND application_id=? AND id=?;

-- name: PutProfile :one
INSERT INTO appconfig_profiles (partition, account_id, region, application_id, id, name, description, location_uri, retrieval_role_arn, type, kms_key_identifier, kms_key_arn, last_poll, next_version, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, application_id, id) DO UPDATE SET name=excluded.name, description=excluded.description, location_uri=excluded.location_uri, retrieval_role_arn=excluded.retrieval_role_arn, type=excluded.type, kms_key_identifier=excluded.kms_key_identifier, kms_key_arn=excluded.kms_key_arn, last_poll=excluded.last_poll, next_version=excluded.next_version, created_at=excluded.created_at
RETURNING row_id;

-- name: ListProfiles :many
SELECT * FROM appconfig_profiles WHERE partition=? AND account_id=? AND region=? AND application_id=? ORDER BY application_id, id;

-- name: DeleteProfile :exec
DELETE FROM appconfig_profiles WHERE partition=? AND account_id=? AND region=? AND application_id=? AND id=?;

-- name: PutHostedVersion :exec
INSERT INTO appconfig_hosted_versions (partition, account_id, region, application_id, profile_id, number, description, content_type, version_label, kms_key_arn, content)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, application_id, profile_id, number) DO UPDATE SET description=excluded.description, content_type=excluded.content_type, version_label=excluded.version_label, kms_key_arn=excluded.kms_key_arn, content=excluded.content;

-- name: ListHostedVersions :many
SELECT * FROM appconfig_hosted_versions WHERE partition=? AND account_id=? AND region=? AND application_id=? AND profile_id=? ORDER BY application_id, profile_id, number;

-- name: DeleteHostedVersion :exec
DELETE FROM appconfig_hosted_versions WHERE partition=? AND account_id=? AND region=? AND application_id=? AND profile_id=? AND number=?;

-- name: PutStrategy :exec
INSERT INTO appconfig_strategies (partition, account_id, region, id, name, description, growth_type, replicate_to, duration_minutes, final_bake_minutes, growth_factor)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET name=excluded.name, description=excluded.description, growth_type=excluded.growth_type, replicate_to=excluded.replicate_to, duration_minutes=excluded.duration_minutes, final_bake_minutes=excluded.final_bake_minutes, growth_factor=excluded.growth_factor;

-- name: ListStrategies :many
SELECT * FROM appconfig_strategies WHERE partition=? AND account_id=? AND region=? ORDER BY id;

-- name: DeleteStrategy :exec
DELETE FROM appconfig_strategies WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: PutDeployment :one
INSERT INTO appconfig_deployments (partition, account_id, region, application_id, environment_id, profile_id, strategy_id, number, previous_deployment, configuration_name, configuration_version, version_label, location_uri, description, content_type, state, type, experiment_flags, growth_type, kms_key_identifier, kms_key_arn, content, duration_minutes, final_bake_minutes, growth_factor, percentage, started_at, completed_at, due, generation, pipeline_action_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, application_id, environment_id, number) DO UPDATE SET profile_id=excluded.profile_id, strategy_id=excluded.strategy_id, previous_deployment=excluded.previous_deployment, configuration_name=excluded.configuration_name, configuration_version=excluded.configuration_version, version_label=excluded.version_label, location_uri=excluded.location_uri, description=excluded.description, content_type=excluded.content_type, state=excluded.state, type=excluded.type, experiment_flags=excluded.experiment_flags, growth_type=excluded.growth_type, kms_key_identifier=excluded.kms_key_identifier, kms_key_arn=excluded.kms_key_arn, content=excluded.content, duration_minutes=excluded.duration_minutes, final_bake_minutes=excluded.final_bake_minutes, growth_factor=excluded.growth_factor, percentage=excluded.percentage, started_at=excluded.started_at, completed_at=excluded.completed_at, due=excluded.due, generation=excluded.generation, pipeline_action_id=excluded.pipeline_action_id
RETURNING row_id;

-- name: ListDeployments :many
SELECT * FROM appconfig_deployments WHERE partition=? AND account_id=? AND region=? AND application_id=? AND environment_id=? ORDER BY application_id, environment_id, number;

-- name: DeleteDeployment :exec
DELETE FROM appconfig_deployments WHERE partition=? AND account_id=? AND region=? AND application_id=? AND environment_id=? AND number=?;

-- name: PutSession :exec
INSERT INTO appconfig_sessions (partition, account_id, region, token, client_id, application_id, environment_id, profile_id, last_deployment, poll_seconds, created_at, expires_at, next_poll)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, token) DO UPDATE SET client_id=excluded.client_id, application_id=excluded.application_id, environment_id=excluded.environment_id, profile_id=excluded.profile_id, last_deployment=excluded.last_deployment, poll_seconds=excluded.poll_seconds, created_at=excluded.created_at, expires_at=excluded.expires_at, next_poll=excluded.next_poll;

-- name: ListSessions :many
SELECT * FROM appconfig_sessions WHERE partition=? AND account_id=? AND region=? ORDER BY token;

-- name: GetSession :one
SELECT * FROM appconfig_sessions WHERE partition=? AND account_id=? AND region=? AND token=?;

-- name: DeleteSession :exec
DELETE FROM appconfig_sessions WHERE partition=? AND account_id=? AND region=? AND token=?;

-- name: PutExtension :one
INSERT INTO appconfig_extensions (partition, account_id, region, id, name, description, arn, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id, version) DO UPDATE SET name=excluded.name, description=excluded.description, arn=excluded.arn
RETURNING row_id;

-- name: ListExtensions :many
SELECT * FROM appconfig_extensions WHERE partition=? AND account_id=? AND region=? ORDER BY id, version;

-- name: DeleteExtension :exec
DELETE FROM appconfig_extensions WHERE partition=? AND account_id=? AND region=? AND id=? AND version=?;

-- name: PutAssociation :one
INSERT INTO appconfig_associations (partition, account_id, region, id, arn, extension_id, extension_arn, resource_arn, extension_version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET arn=excluded.arn, extension_id=excluded.extension_id, extension_arn=excluded.extension_arn, resource_arn=excluded.resource_arn, extension_version=excluded.extension_version
RETURNING row_id;

-- name: ListAssociations :many
SELECT * FROM appconfig_associations WHERE partition=? AND account_id=? AND region=? ORDER BY id;

-- name: DeleteAssociation :exec
DELETE FROM appconfig_associations WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: ListPendingDeployments :many
SELECT * FROM appconfig_deployments WHERE due != sqlc.arg(zero_due) ORDER BY due, partition, account_id, region, application_id, environment_id, number;

-- name: InsertMonitor :exec
INSERT INTO appconfig_environment_monitors (parent_id, ordinal, alarm_arn, role_arn) VALUES (?, ?, ?, ?);

-- name: ListMonitors :many
SELECT * FROM appconfig_environment_monitors WHERE parent_id=? ORDER BY ordinal;

-- name: ClearMonitors :exec
DELETE FROM appconfig_environment_monitors WHERE parent_id=?;

-- name: InsertValidator :exec
INSERT INTO appconfig_profile_validators (parent_id, ordinal, type, content) VALUES (?, ?, ?, ?);

-- name: ListValidators :many
SELECT * FROM appconfig_profile_validators WHERE parent_id=? ORDER BY ordinal;

-- name: ClearValidators :exec
DELETE FROM appconfig_profile_validators WHERE parent_id=?;

-- name: InsertExtensionAction :exec
INSERT INTO appconfig_extension_actions (parent_id, ordinal, point, name, description, uri, role_arn) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListExtensionActions :many
SELECT * FROM appconfig_extension_actions WHERE parent_id=? ORDER BY ordinal;

-- name: ClearExtensionActions :exec
DELETE FROM appconfig_extension_actions WHERE parent_id=?;

-- name: InsertExtensionParameter :exec
INSERT INTO appconfig_extension_parameters (parent_id, ordinal, name, description, required, dynamic) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListExtensionParameters :many
SELECT * FROM appconfig_extension_parameters WHERE parent_id=? ORDER BY ordinal;

-- name: ClearExtensionParameters :exec
DELETE FROM appconfig_extension_parameters WHERE parent_id=?;

-- name: InsertDeploymentEvent :one
INSERT INTO appconfig_deployment_events (parent_id, ordinal, type, description, triggered_by, at) VALUES (?, ?, ?, ?, ?, ?) RETURNING row_id;

-- name: ListDeploymentEvents :many
SELECT * FROM appconfig_deployment_events WHERE parent_id=? ORDER BY ordinal;

-- name: ClearDeploymentEvents :exec
DELETE FROM appconfig_deployment_events WHERE parent_id=?;

-- name: InsertActionInvocation :exec
INSERT INTO appconfig_deployment_invocations (parent_id, ordinal, id, extension_id, action_name, uri, role_arn, error_code, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListActionInvocations :many
SELECT * FROM appconfig_deployment_invocations WHERE parent_id=? ORDER BY ordinal;

-- name: InsertAppliedExtension :one
INSERT INTO appconfig_deployment_extensions (parent_id, ordinal, association_id, extension_id, version) VALUES (?, ?, ?, ?, ?) RETURNING row_id;

-- name: ListAppliedExtensions :many
SELECT * FROM appconfig_deployment_extensions WHERE parent_id=? ORDER BY ordinal;

-- name: ClearAppliedExtensions :exec
DELETE FROM appconfig_deployment_extensions WHERE parent_id=?;

-- name: InsertAssociationParameter :exec
INSERT INTO appconfig_association_parameters (parent_id,name,value) VALUES (?,?,?);

-- name: ListAssociationParameters :many
SELECT name,value FROM appconfig_association_parameters WHERE parent_id=? ORDER BY name;

-- name: ClearAssociationParameters :exec
DELETE FROM appconfig_association_parameters WHERE parent_id=?;

-- name: InsertAppliedExtensionParameter :exec
INSERT INTO appconfig_deployment_extension_parameters (parent_id,name,value) VALUES (?,?,?);

-- name: ListAppliedExtensionParameters :many
SELECT name,value FROM appconfig_deployment_extension_parameters WHERE parent_id=? ORDER BY name;

-- name: InsertAppliedExtensionAction :exec
INSERT INTO appconfig_deployment_extension_actions (parent_id,ordinal,point,name,description,uri,role_arn) VALUES (?,?,?,?,?,?,?);

-- name: ListAppliedExtensionActions :many
SELECT * FROM appconfig_deployment_extension_actions WHERE parent_id=? ORDER BY ordinal;

-- name: InsertDynamicParameter :one
INSERT INTO appconfig_deployment_dynamic_parameters (parent_id,name) VALUES (?,?) RETURNING row_id;

-- name: ListDynamicParameters :many
SELECT * FROM appconfig_deployment_dynamic_parameters WHERE parent_id=? ORDER BY name;

-- name: ClearDynamicParameters :exec
DELETE FROM appconfig_deployment_dynamic_parameters WHERE parent_id=?;

-- name: InsertDynamicValue :exec
INSERT INTO appconfig_deployment_dynamic_values (parent_id,ordinal,value) VALUES (?,?,?);

-- name: ListDynamicValues :many
SELECT value FROM appconfig_deployment_dynamic_values WHERE parent_id=? ORDER BY ordinal;

-- name: ListTags :many
SELECT key,value FROM appconfig_tags WHERE partition=? AND account_id=? AND region=? AND arn=? ORDER BY key;

-- name: InsertTag :exec
INSERT INTO appconfig_tags (partition,account_id,region,arn,key,value) VALUES (?,?,?,?,?,?);

-- name: ClearTags :exec
DELETE FROM appconfig_tags WHERE partition=? AND account_id=? AND region=? AND arn=?;

-- name: GetSettings :one
SELECT * FROM appconfig_settings WHERE partition=? AND account_id=? AND region=?;

-- name: PutSettings :exec
INSERT INTO appconfig_settings (partition,account_id,region,deletion_protection_enabled,protection_minutes,vended_metrics_enabled,vended_metrics_set)
VALUES (?,?,?,?,?,?,?) ON CONFLICT (partition,account_id,region) DO UPDATE SET
 deletion_protection_enabled=excluded.deletion_protection_enabled,
 protection_minutes=excluded.protection_minutes, vended_metrics_enabled=excluded.vended_metrics_enabled,
 vended_metrics_set=excluded.vended_metrics_set;
