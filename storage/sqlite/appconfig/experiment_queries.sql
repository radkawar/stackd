-- name: PutExperimentDefinition :one
INSERT INTO appconfig_experiment_definitions (partition,account_id,region,application_id,id,snapshot_number,name,environment_id,profile_id,flag_key,audience_rule,audience_description,hypothesis,launch_criteria,kms_key_identifier,status,created_at,updated_at,cfn_owner,cfn_token)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,application_id,id,snapshot_number) DO UPDATE SET name=excluded.name,environment_id=excluded.environment_id,profile_id=excluded.profile_id,flag_key=excluded.flag_key,audience_rule=excluded.audience_rule,audience_description=excluded.audience_description,hypothesis=excluded.hypothesis,launch_criteria=excluded.launch_criteria,kms_key_identifier=excluded.kms_key_identifier,status=excluded.status,created_at=excluded.created_at,updated_at=excluded.updated_at RETURNING row_id;

-- name: ListExperimentDefinitions :many
SELECT * FROM appconfig_experiment_definitions WHERE partition=? AND account_id=? AND region=? AND (application_id=sqlc.arg(application_id) OR sqlc.arg(application_id)='') AND snapshot_number=0 ORDER BY application_id,id;

-- name: GetExperimentDefinitionRow :one
SELECT * FROM appconfig_experiment_definitions WHERE partition=? AND account_id=? AND region=? AND application_id=? AND id=? AND snapshot_number=?;

-- name: DeleteExperimentDefinition :exec
DELETE FROM appconfig_experiment_definitions WHERE partition=? AND account_id=? AND region=? AND application_id=? AND id=?;

-- name: DeleteExperimentTreatments :exec
DELETE FROM appconfig_experiment_treatments WHERE definition_row=?;

-- name: PutExperimentTreatment :one
INSERT INTO appconfig_experiment_treatments (definition_row,ordinal,treatment_key,description,weight,enabled) VALUES (?,?,?,?,?,?) RETURNING row_id;

-- name: ListExperimentTreatments :many
SELECT * FROM appconfig_experiment_treatments WHERE definition_row=? ORDER BY ordinal;

-- name: PutExperimentAttribute :one
INSERT INTO appconfig_experiment_attributes (treatment_row,name,kind,boolean_value,number_value,string_value) VALUES (?,?,?,?,?,?) RETURNING row_id;

-- name: ListExperimentAttributes :many
SELECT * FROM appconfig_experiment_attributes WHERE treatment_row=? ORDER BY name;

-- name: PutExperimentAttributeItem :exec
INSERT INTO appconfig_experiment_attribute_items (attribute_row,ordinal,number_value,string_value) VALUES (?,?,?,?);

-- name: ListExperimentAttributeItems :many
SELECT * FROM appconfig_experiment_attribute_items WHERE attribute_row=? ORDER BY ordinal;

-- name: PutExperimentRun :one
INSERT INTO appconfig_experiment_runs (definition_row,number,description,status,exposure,has_overrides,has_result,executive_summary,reasons_to_launch,reasons_not_to_launch,started_at,updated_at,ended_at,cfn_owner,cfn_token)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(definition_row,number) DO UPDATE SET description=excluded.description,status=excluded.status,exposure=excluded.exposure,has_overrides=excluded.has_overrides,has_result=excluded.has_result,executive_summary=excluded.executive_summary,reasons_to_launch=excluded.reasons_to_launch,reasons_not_to_launch=excluded.reasons_not_to_launch,started_at=excluded.started_at,updated_at=excluded.updated_at,ended_at=excluded.ended_at RETURNING row_id;

-- name: ListExperimentRuns :many
SELECT * FROM appconfig_experiment_runs WHERE definition_row=? ORDER BY number;

-- name: DeleteExperimentOverrides :exec
DELETE FROM appconfig_experiment_overrides WHERE run_row=?;

-- name: PutExperimentOverride :exec
INSERT INTO appconfig_experiment_overrides (run_row,entity_id,treatment_key) VALUES (?,?,?);

-- name: ListExperimentOverrides :many
SELECT * FROM appconfig_experiment_overrides WHERE run_row=? ORDER BY entity_id;

-- name: DeleteExperimentEvents :exec
DELETE FROM appconfig_experiment_events WHERE run_row=?;

-- name: PutExperimentEvent :one
INSERT INTO appconfig_experiment_events (run_row,ordinal,type,description,triggered_by,deployment_arn,occurred_at,exposure,has_overrides) VALUES (?,?,?,?,?,?,?,?,?) RETURNING row_id;

-- name: ListExperimentEvents :many
SELECT * FROM appconfig_experiment_events WHERE run_row=? ORDER BY ordinal;

-- name: PutExperimentEventOverride :exec
INSERT INTO appconfig_experiment_event_overrides (event_row,entity_id,treatment_key) VALUES (?,?,?);

-- name: ListExperimentEventOverrides :many
SELECT * FROM appconfig_experiment_event_overrides WHERE event_row=? ORDER BY entity_id;
