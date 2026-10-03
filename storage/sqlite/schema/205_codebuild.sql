-- Resource identity and execution state are relational. Nested API configuration
-- documents occupy separate columns; imported credentials retain KMS ciphertext.
CREATE TABLE codebuild_projects (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 project_name TEXT NOT NULL,
 build_number INTEGER NOT NULL,
 arn TEXT,
 name TEXT,
 auto_retry_limit INTEGER,
 concurrent_build_limit INTEGER,
 created DATETIME,
 description TEXT,
 encryption_key TEXT,
 last_modified DATETIME,
 project_visibility TEXT,
 public_project_alias TEXT,
 queued_timeout_in_minutes INTEGER,
 resource_access_role TEXT,
 service_role TEXT,
 source_version TEXT,
 timeout_in_minutes INTEGER,
 artifacts BLOB NOT NULL,
 badge BLOB NOT NULL,
 build_batch_config BLOB NOT NULL,
 cache BLOB NOT NULL,
 environment BLOB NOT NULL,
 file_system_locations BLOB NOT NULL,
 logs_config BLOB NOT NULL,
 secondary_artifacts BLOB NOT NULL,
 secondary_sources BLOB NOT NULL,
 source BLOB NOT NULL,
 vpc_config BLOB NOT NULL,
 webhook BLOB NOT NULL,
 environment_variables_present BOOLEAN NOT NULL,
 secondary_source_versions_present BOOLEAN NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, project_name)
);

-- Builds deliberately do not reference projects: deleting a project must not
-- delete accepted work, its resolved configuration or retained build history.
CREATE TABLE codebuild_builds (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 accepted_event_id TEXT NOT NULL,
 idempotency_token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 deadline DATETIME,
 queued_deadline DATETIME,
 stop_requested BOOLEAN NOT NULL,
 delete_requested BOOLEAN NOT NULL,
 cleanup_pending BOOLEAN NOT NULL,
 credential_token TEXT NOT NULL,
 log_offset INTEGER NOT NULL,
 failure TEXT NOT NULL,
 fleet_arn TEXT NOT NULL,
 arn TEXT,
 build_id TEXT,
 build_batch_arn TEXT,
 build_complete BOOLEAN,
 build_number INTEGER,
 build_status TEXT,
 current_phase TEXT,
 encryption_key TEXT,
 end_time DATETIME,
 initiator TEXT,
 project_name TEXT,
 queued_timeout_in_minutes INTEGER,
 resolved_source_version TEXT,
 service_role TEXT,
 source_version TEXT,
 start_time DATETIME,
 timeout_in_minutes INTEGER,
 artifacts_config BLOB NOT NULL,
 logs_config BLOB NOT NULL,
 artifacts BLOB NOT NULL,
 auto_retry_config BLOB NOT NULL,
 cache BLOB NOT NULL,
 debug_session BLOB NOT NULL,
 environment BLOB NOT NULL,
 file_system_locations BLOB NOT NULL,
 logs BLOB NOT NULL,
 network_interface BLOB NOT NULL,
 secondary_artifacts BLOB NOT NULL,
 secondary_sources BLOB NOT NULL,
 source BLOB NOT NULL,
 vpc_config BLOB NOT NULL,
 environment_variables_present BOOLEAN NOT NULL,
 exported_environment_variables_present BOOLEAN NOT NULL,
 phases_present BOOLEAN NOT NULL,
 report_arns_present BOOLEAN NOT NULL,
 secondary_source_versions_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id)
);
CREATE INDEX codebuild_active_builds ON codebuild_builds (partition, account_id, region, resource_id) WHERE build_complete IS NULL OR build_complete = 0 OR delete_requested = 1 OR cleanup_pending = 1;
CREATE INDEX codebuild_project_builds ON codebuild_builds (partition, account_id, region, project_name, start_time, resource_id);

CREATE TABLE codebuild_fleets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 fleet_name TEXT NOT NULL,
 arn TEXT,
 name TEXT,
 fleet_id TEXT,
 base_capacity INTEGER,
 compute_type TEXT,
 created DATETIME,
 environment_type TEXT,
 fleet_service_role TEXT,
 image_id TEXT,
 last_modified DATETIME,
 overflow_behavior TEXT,
 compute_configuration BLOB NOT NULL,
 proxy_configuration BLOB NOT NULL,
 scaling_configuration BLOB NOT NULL,
 status BLOB NOT NULL,
 vpc_config BLOB NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, fleet_name)
);

CREATE TABLE codebuild_credentials (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 server_type TEXT NOT NULL,
 auth_type TEXT NOT NULL,
 arn TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, server_type, auth_type)
);

CREATE TABLE codebuild_project_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 project_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 tag_key TEXT,
 tag_value TEXT,
 PRIMARY KEY (partition, account_id, region, project_name, position),
 FOREIGN KEY (partition, account_id, region, project_name) REFERENCES codebuild_projects (partition, account_id, region, project_name) ON DELETE CASCADE
);
CREATE TABLE codebuild_fleet_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 fleet_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 tag_key TEXT,
 tag_value TEXT,
 PRIMARY KEY (partition, account_id, region, fleet_name, position),
 FOREIGN KEY (partition, account_id, region, fleet_name) REFERENCES codebuild_fleets (partition, account_id, region, fleet_name) ON DELETE CASCADE
);
CREATE TABLE codebuild_project_variables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 project_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT,
 value TEXT,
 type TEXT,
 PRIMARY KEY (partition, account_id, region, project_name, position),
 FOREIGN KEY (partition, account_id, region, project_name) REFERENCES codebuild_projects (partition, account_id, region, project_name) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_variables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT,
 value TEXT,
 type TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_project_source_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 project_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 source_identifier TEXT,
 source_version TEXT,
 PRIMARY KEY (partition, account_id, region, project_name, position),
 FOREIGN KEY (partition, account_id, region, project_name) REFERENCES codebuild_projects (partition, account_id, region, project_name) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_source_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 source_identifier TEXT,
 source_version TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_exported_variables (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT,
 value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_report_arns (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_phases (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 duration_in_seconds INTEGER,
 end_time DATETIME,
 phase_status TEXT,
 phase_type TEXT,
 start_time DATETIME,
 contexts_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_id, position),
 FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES codebuild_builds (partition, account_id, region, resource_id) ON DELETE CASCADE
);
CREATE TABLE codebuild_build_phase_contexts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 phase_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 message TEXT,
 status_code TEXT,
 PRIMARY KEY (partition, account_id, region, resource_id, phase_position, position),
 FOREIGN KEY (partition, account_id, region, resource_id, phase_position) REFERENCES codebuild_build_phases (partition, account_id, region, resource_id, position) ON DELETE CASCADE
);
