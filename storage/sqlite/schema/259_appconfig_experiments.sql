CREATE TABLE appconfig_experiment_definitions (
 row_id INTEGER PRIMARY KEY,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 application_id TEXT NOT NULL, id TEXT NOT NULL, snapshot_number INTEGER NOT NULL,
 name TEXT NOT NULL, environment_id TEXT NOT NULL, profile_id TEXT NOT NULL, flag_key TEXT NOT NULL,
 audience_rule TEXT NOT NULL, audience_description TEXT NOT NULL, hypothesis TEXT NOT NULL,
 launch_criteria TEXT NOT NULL, kms_key_identifier TEXT NOT NULL, status TEXT NOT NULL,
 created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL,
 UNIQUE (partition,account_id,region,application_id,id,snapshot_number)
);
CREATE TABLE appconfig_experiment_treatments (
 row_id INTEGER PRIMARY KEY,
 definition_row INTEGER NOT NULL REFERENCES appconfig_experiment_definitions(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, treatment_key TEXT NOT NULL, description TEXT NOT NULL,
 weight REAL NOT NULL, enabled INTEGER NOT NULL,
 UNIQUE(definition_row,ordinal)
);
CREATE TABLE appconfig_experiment_attributes (
 row_id INTEGER PRIMARY KEY,
 treatment_row INTEGER NOT NULL REFERENCES appconfig_experiment_treatments(row_id) ON DELETE CASCADE,
 name TEXT NOT NULL, kind TEXT NOT NULL, boolean_value INTEGER NOT NULL,
 number_value REAL NOT NULL, string_value TEXT NOT NULL,
 UNIQUE(treatment_row,name)
);
CREATE TABLE appconfig_experiment_attribute_items (
 attribute_row INTEGER NOT NULL REFERENCES appconfig_experiment_attributes(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, number_value REAL NOT NULL, string_value TEXT NOT NULL,
 PRIMARY KEY(attribute_row,ordinal)
);
CREATE TABLE appconfig_experiment_runs (
 row_id INTEGER PRIMARY KEY,
 definition_row INTEGER NOT NULL REFERENCES appconfig_experiment_definitions(row_id) ON DELETE CASCADE,
 number INTEGER NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, exposure REAL NOT NULL,
 has_overrides INTEGER NOT NULL, has_result INTEGER NOT NULL,
 executive_summary TEXT NOT NULL, reasons_to_launch TEXT NOT NULL, reasons_not_to_launch TEXT NOT NULL,
 started_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, ended_at TIMESTAMP NOT NULL,
 UNIQUE(definition_row,number)
);
CREATE TABLE appconfig_experiment_overrides (
 run_row INTEGER NOT NULL REFERENCES appconfig_experiment_runs(row_id) ON DELETE CASCADE,
 entity_id TEXT NOT NULL, treatment_key TEXT NOT NULL, PRIMARY KEY(run_row,entity_id)
);
CREATE TABLE appconfig_experiment_events (
 row_id INTEGER PRIMARY KEY,
 run_row INTEGER NOT NULL REFERENCES appconfig_experiment_runs(row_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, type TEXT NOT NULL, description TEXT NOT NULL,
 triggered_by TEXT NOT NULL, deployment_arn TEXT NOT NULL, occurred_at TIMESTAMP NOT NULL,
 exposure REAL, has_overrides INTEGER NOT NULL, UNIQUE(run_row,ordinal)
);
CREATE TABLE appconfig_experiment_event_overrides (
 event_row INTEGER NOT NULL REFERENCES appconfig_experiment_events(row_id) ON DELETE CASCADE,
 entity_id TEXT NOT NULL, treatment_key TEXT NOT NULL, PRIMARY KEY(event_row,entity_id)
);
