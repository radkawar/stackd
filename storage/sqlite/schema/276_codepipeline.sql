CREATE TABLE codepipeline_pipelines (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 PRIMARY KEY (incarnation)
);

CREATE TABLE codepipeline_tags (
 incarnation TEXT NOT NULL,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY (incarnation,tag_key)
);

CREATE TABLE codepipeline_transitions (
 incarnation TEXT NOT NULL,
 stage_name TEXT NOT NULL,
 transition_type TEXT NOT NULL,
 disabled INTEGER NOT NULL,
 reason TEXT NOT NULL,
 changed_by TEXT NOT NULL,
 changed_at INTEGER NOT NULL,
 PRIMARY KEY (incarnation,stage_name,transition_type)
);

CREATE TABLE codepipeline_definitions (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 execution_mode TEXT NOT NULL,
 pipeline_type TEXT NOT NULL,
 artifact_bucket TEXT NOT NULL,
 encryption_key TEXT NOT NULL,
 encryption_type TEXT NOT NULL,
 PRIMARY KEY (incarnation,version)
);

CREATE TABLE codepipeline_stages (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 stage_index INTEGER NOT NULL,
 name TEXT NOT NULL,
 PRIMARY KEY (incarnation,version,stage_index)
);

CREATE TABLE codepipeline_actions (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 stage_index INTEGER NOT NULL,
 action_index INTEGER NOT NULL,
 name TEXT NOT NULL,
 category TEXT NOT NULL,
 owner TEXT NOT NULL,
 provider TEXT NOT NULL,
 action_version TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 region TEXT NOT NULL,
 run_order INTEGER NOT NULL,
 timeout_minutes INTEGER NOT NULL,
 namespace TEXT NOT NULL,
 PRIMARY KEY (incarnation,version,stage_index,action_index)
);

CREATE TABLE codepipeline_configuration (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 stage_index INTEGER NOT NULL,
 action_index INTEGER NOT NULL,
 config_key TEXT NOT NULL,
 config_value TEXT NOT NULL,
 PRIMARY KEY (incarnation,version,stage_index,action_index,config_key)
);

CREATE TABLE codepipeline_declarations (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 stage_index INTEGER NOT NULL,
 action_index INTEGER NOT NULL,
 direction TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 PRIMARY KEY (incarnation,version,stage_index,action_index,direction,position)
);

CREATE TABLE codepipeline_executions (
 execution_id TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pipeline_name TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 client_token TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 mode TEXT NOT NULL,
 status TEXT NOT NULL,
 summary TEXT NOT NULL,
 trigger_type TEXT NOT NULL,
 trigger_detail TEXT NOT NULL,
 stop_reason TEXT NOT NULL,
 stage_index INTEGER NOT NULL,
 stage_entered INTEGER NOT NULL,
 updated_definition INTEGER NOT NULL,
 started_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 due INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 sequence INTEGER NOT NULL,
 parent_event_id TEXT NOT NULL,
 attempt INTEGER NOT NULL,
 stage_status TEXT NOT NULL,
 stage_started_at INTEGER NOT NULL,
 last_retry_at INTEGER NOT NULL,
 stage_last_retry_at INTEGER NOT NULL,
 PRIMARY KEY (execution_id)
);

CREATE TABLE codepipeline_overrides (
 execution_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 action_name TEXT NOT NULL,
 revision_type TEXT NOT NULL,
 revision_value TEXT NOT NULL,
 PRIMARY KEY (execution_id,position)
);

CREATE TABLE codepipeline_revisions (
 execution_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 action_name TEXT NOT NULL,
 artifact_name TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 change_id TEXT NOT NULL,
 summary TEXT NOT NULL,
 url TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY (execution_id,position)
);

CREATE TABLE codepipeline_action_executions (
 action_id TEXT NOT NULL,
 execution_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 stage_name TEXT NOT NULL,
 action_name TEXT NOT NULL,
 status TEXT NOT NULL,
 stage_index INTEGER NOT NULL,
 action_index INTEGER NOT NULL,
 attempt INTEGER NOT NULL,
 started_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 external_id TEXT NOT NULL,
 external_url TEXT NOT NULL,
 summary TEXT NOT NULL,
 error_code TEXT NOT NULL,
 error_message TEXT NOT NULL,
 approval_token TEXT NOT NULL,
 updated_by TEXT NOT NULL,
 PRIMARY KEY (action_id)
);

CREATE TABLE codepipeline_artifacts (
 action_id TEXT NOT NULL,
 direction TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 bucket TEXT NOT NULL,
 object_key TEXT NOT NULL,
 version_id TEXT NOT NULL,
 etag TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 producer_id TEXT NOT NULL,
 PRIMARY KEY (action_id,direction,position)
);
CREATE UNIQUE INDEX codepipeline_pipeline_names ON codepipeline_pipelines(partition,account_id,region,name);
CREATE INDEX codepipeline_execution_scope ON codepipeline_executions(partition,account_id,region,incarnation,sequence);
CREATE INDEX codepipeline_execution_due ON codepipeline_executions(due) WHERE due != 0;
CREATE INDEX codepipeline_action_parent ON codepipeline_action_executions(execution_id,position);

CREATE TABLE codepipeline_action_values (
 action_id TEXT NOT NULL,
 value_kind TEXT NOT NULL,
 value_key TEXT NOT NULL,
 value_text TEXT NOT NULL,
 PRIMARY KEY (action_id,value_kind,value_key)
);
