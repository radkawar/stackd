CREATE TABLE pipes_pipes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 version INTEGER NOT NULL,
 description TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 source_arn TEXT NOT NULL,
 target_arn TEXT NOT NULL,
 enrichment_arn TEXT NOT NULL,
 state TEXT NOT NULL,
 desired TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_ns INTEGER NOT NULL,
 modified_ns INTEGER NOT NULL,
 due_ns INTEGER NOT NULL,
 source_kind TEXT NOT NULL,
 starting_position TEXT NOT NULL,
 starting_time_ns INTEGER,
 batch_size INTEGER NOT NULL,
 window_seconds INTEGER NOT NULL,
 maximum_age INTEGER NOT NULL,
 maximum_retries INTEGER NOT NULL,
 parallelism INTEGER NOT NULL,
 automatic_bisect INTEGER NOT NULL,
 dlq_arn TEXT NOT NULL,
 enrichment_template TEXT NOT NULL,
 parent_event_id TEXT NOT NULL,
 target_template TEXT,
 target_group_id TEXT,
 target_deduplication_id TEXT,
 target_partition_key TEXT,
 target_lambda_invocation TEXT,
 target_states_invocation TEXT,
 target_log_stream TEXT,
 target_log_timestamp TEXT,
 target_event_source TEXT,
 target_event_detail_type TEXT,
 target_event_time TEXT,
 target_event_endpoint TEXT,
 target_ecs_task_definition TEXT,
 target_ecs_task_count INTEGER,
 target_ecs_launch_type TEXT,
 target_ecs_group TEXT,
 target_ecs_platform_version TEXT,
 target_ecs_propagate_tags TEXT,
 target_ecs_reference_id TEXT,
 target_ecs_enable_managed_tags INTEGER,
 target_ecs_enable_execute_command INTEGER,
 target_ecs_capacity_strategy TEXT,
 target_ecs_network TEXT,
 target_ecs_overrides TEXT,
 target_ecs_placement_constraints TEXT,
 target_ecs_placement_strategy TEXT,
 target_ecs_tags TEXT,
 PRIMARY KEY(partition,account_id,region,name)
);
CREATE INDEX pipes_due ON pipes_pipes(state,due_ns,id);
CREATE TABLE pipes_tags (
 pipe_id TEXT NOT NULL REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(pipe_id,key)
);
CREATE TABLE pipes_filters (
 pipe_id TEXT NOT NULL REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 pattern TEXT NOT NULL,
 PRIMARY KEY(pipe_id,position)
);
CREATE TABLE pipes_target_event_resources (
 pipe_id TEXT NOT NULL REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY(pipe_id,position)
);
CREATE TABLE pipes_checkpoints (
 pipe_id TEXT NOT NULL REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 shard_id TEXT NOT NULL,
 parent_id TEXT NOT NULL,
 adjacent_parent_id TEXT NOT NULL,
 sequence TEXT NOT NULL,
 iterator TEXT NOT NULL,
 initialized INTEGER NOT NULL,
 closed INTEGER NOT NULL,
 PRIMARY KEY(pipe_id,shard_id)
);
CREATE TABLE pipes_work (
 id TEXT PRIMARY KEY,
 pipe_id TEXT NOT NULL REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 shard_id TEXT NOT NULL,
 record_id TEXT NOT NULL,
 sequence TEXT NOT NULL,
 receipt TEXT NOT NULL,
 group_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 event BLOB NOT NULL,
 created_ns INTEGER NOT NULL,
 due_ns INTEGER NOT NULL,
 attempts INTEGER NOT NULL,
 batch_limit INTEGER NOT NULL,
 phase TEXT NOT NULL,
 last_error TEXT NOT NULL
);
CREATE INDEX pipes_work_order ON pipes_work(pipe_id,ordinal,id);
CREATE TABLE pipes_encryption (
 pipe_id TEXT PRIMARY KEY REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 key_arn TEXT NOT NULL,
 wrapped_key BLOB NOT NULL,
 nonce BLOB NOT NULL,
 ciphertext BLOB NOT NULL
);
CREATE TABLE pipes_logging (
 pipe_id TEXT PRIMARY KEY REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 level TEXT NOT NULL,
 include_execution_data INTEGER NOT NULL,
 log_group_arn TEXT NOT NULL,
 firehose_arn TEXT NOT NULL,
 bucket_name TEXT NOT NULL,
 bucket_owner TEXT NOT NULL,
 prefix TEXT NOT NULL,
 output_format TEXT NOT NULL
);
