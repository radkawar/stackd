-- Revisions have no foreign key to the current machine: retained executions own
-- their admitted configuration independently of control-plane resource lifetime.
CREATE TABLE stepfunctions_revisions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 created DATETIME NOT NULL,
 definition TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 log_group_arn TEXT NOT NULL,
 initial BOOLEAN NOT NULL,
 log_level TEXT NOT NULL,
 include_execution_data BOOLEAN NOT NULL,
 tracing_enabled BOOLEAN NOT NULL,
 encryption_type TEXT NOT NULL,
 kms_key_arn TEXT NOT NULL,
 data_key_reuse_seconds INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, id)
);

CREATE TABLE stepfunctions_machines (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 type TEXT NOT NULL,
 status TEXT NOT NULL,
 created DATETIME NOT NULL,
 version INTEGER NOT NULL,
 delete_at DATETIME,
 next_version INTEGER NOT NULL,
 first_version_description TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name),
 UNIQUE (partition, account_id, region, name, id),
 FOREIGN KEY (partition, account_id, region, revision_id)
 REFERENCES stepfunctions_revisions(partition, account_id, region, id)
);
CREATE INDEX stepfunctions_machines_deletion ON stepfunctions_machines(delete_at, partition, account_id, region, name) WHERE delete_at IS NOT NULL;
CREATE INDEX stepfunctions_machines_revision ON stepfunctions_machines(partition, account_id, region, revision_id);

CREATE TABLE stepfunctions_machine_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, machine_name, key),
 FOREIGN KEY (partition, account_id, region, machine_name)
 REFERENCES stepfunctions_machines(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE stepfunctions_versions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 number INTEGER NOT NULL,
 revision_id TEXT NOT NULL,
 created DATETIME NOT NULL,
 description TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, machine_name, machine_id, number),
 FOREIGN KEY (partition, account_id, region, machine_name, machine_id)
 REFERENCES stepfunctions_machines(partition, account_id, region, name, id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, revision_id)
 REFERENCES stepfunctions_revisions(partition, account_id, region, id)
);
CREATE INDEX stepfunctions_versions_revision ON stepfunctions_versions(partition, account_id, region, revision_id);

CREATE TABLE stepfunctions_aliases (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 created DATETIME NOT NULL,
 updated DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, machine_name, machine_id, name),
 FOREIGN KEY (partition, account_id, region, machine_name, machine_id)
 REFERENCES stepfunctions_machines(partition, account_id, region, name, id) ON DELETE CASCADE
);
CREATE TABLE stepfunctions_alias_routes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 alias_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 version INTEGER NOT NULL,
 weight INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, machine_name, machine_id, alias_name, position),
 FOREIGN KEY (partition, account_id, region, machine_name, machine_id, alias_name)
 REFERENCES stepfunctions_aliases(partition, account_id, region, machine_name, machine_id, name) ON DELETE CASCADE
);

CREATE TABLE stepfunctions_activities (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL,
 created DATETIME NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE stepfunctions_activity_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 activity_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, activity_name, key),
 FOREIGN KEY (partition, account_id, region, activity_name)
 REFERENCES stepfunctions_activities(partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE stepfunctions_executions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 machine_name TEXT NOT NULL,
 machine_id TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 name TEXT NOT NULL,
 type TEXT NOT NULL,
 version_arn TEXT NOT NULL,
 alias_arn TEXT NOT NULL,
 map_run_arn TEXT NOT NULL,
 map_item_count INTEGER NOT NULL,
 parent_event_id TEXT NOT NULL,
 trace_header TEXT NOT NULL,
 status TEXT NOT NULL,
 input TEXT NOT NULL,
 output TEXT NOT NULL,
 error TEXT NOT NULL,
 cause TEXT NOT NULL,
 started DATETIME NOT NULL,
 stopped DATETIME,
 deadline DATETIME NOT NULL,
 expires DATETIME,
 version INTEGER NOT NULL,
 next_frame_id INTEGER NOT NULL,
 next_history_id INTEGER NOT NULL,
 delivered_history_id INTEGER NOT NULL,
 peak_memory_bytes INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn),
 FOREIGN KEY (partition, account_id, region, revision_id)
 REFERENCES stepfunctions_revisions(partition, account_id, region, id)
);
CREATE INDEX stepfunctions_executions_machine ON stepfunctions_executions(partition, account_id, region, machine_id, started DESC, arn);
CREATE INDEX stepfunctions_executions_list ON stepfunctions_executions(partition, account_id, region, started DESC, arn);
CREATE INDEX stepfunctions_executions_map_run ON stepfunctions_executions(partition, account_id, region, map_run_arn, started DESC, arn);
CREATE INDEX stepfunctions_executions_revision ON stepfunctions_executions(partition, account_id, region, revision_id);
CREATE INDEX stepfunctions_executions_timeout ON stepfunctions_executions(deadline, partition, account_id, region, arn) WHERE status = 'RUNNING';
CREATE INDEX stepfunctions_executions_expiry ON stepfunctions_executions(expires, partition, account_id, region, arn) WHERE status <> 'RUNNING' AND expires IS NOT NULL;
CREATE INDEX stepfunctions_executions_history_delivery ON stepfunctions_executions(partition, account_id, region, arn) WHERE delivered_history_id < next_history_id;

CREATE TABLE stepfunctions_frames (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 id INTEGER NOT NULL,
 parent_id INTEGER NOT NULL,
 parent_state_id INTEGER NOT NULL,
 parent_attempt INTEGER NOT NULL,
 branch_index INTEGER NOT NULL,
 scope_path TEXT NOT NULL,
 state_name TEXT NOT NULL,
 phase TEXT NOT NULL,
 input TEXT NOT NULL,
 variables TEXT NOT NULL,
 arguments TEXT NOT NULL,
 output TEXT NOT NULL,
 error TEXT NOT NULL,
 cause TEXT NOT NULL,
 entered DATETIME NOT NULL,
 entered_history_id INTEGER NOT NULL,
 previous_history_id INTEGER NOT NULL,
 task_id TEXT NOT NULL,
 retry_count INTEGER NOT NULL,
 next_item INTEGER NOT NULL,
 item_count INTEGER NOT NULL,
 max_concurrency INTEGER NOT NULL,
 map_run_arn TEXT NOT NULL,
 due DATETIME,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, execution_arn, id),
 FOREIGN KEY (partition, account_id, region, execution_arn)
 REFERENCES stepfunctions_executions(partition, account_id, region, arn) ON DELETE CASCADE
);
CREATE INDEX stepfunctions_frames_work ON stepfunctions_frames(due, partition, account_id, region, execution_arn, id) WHERE due IS NOT NULL;
CREATE TABLE stepfunctions_frame_retries (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 frame_id INTEGER NOT NULL,
 retrier INTEGER NOT NULL,
 count INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, execution_arn, frame_id, retrier),
 FOREIGN KEY (partition, account_id, region, execution_arn, frame_id)
 REFERENCES stepfunctions_frames(partition, account_id, region, execution_arn, id) ON DELETE CASCADE
);

CREATE TABLE stepfunctions_tasks (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 frame_id INTEGER NOT NULL,
 attempt INTEGER NOT NULL,
 token TEXT NOT NULL,
 kind TEXT NOT NULL,
 resource TEXT NOT NULL,
 parameters TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 activity TEXT NOT NULL,
 status TEXT NOT NULL,
 scheduled DATETIME NOT NULL,
 started DATETIME,
 timeout_seconds INTEGER NOT NULL,
 heartbeat_seconds INTEGER NOT NULL,
 deadline DATETIME,
 heartbeat_deadline DATETIME,
 worker_name TEXT NOT NULL,
 output TEXT NOT NULL,
 error TEXT NOT NULL,
 cause TEXT NOT NULL,
 child_execution_arn TEXT NOT NULL,
 history_id INTEGER NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, id),
 FOREIGN KEY (partition, account_id, region, execution_arn, frame_id)
 REFERENCES stepfunctions_frames(partition, account_id, region, execution_arn, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX stepfunctions_tasks_token ON stepfunctions_tasks(partition, account_id, region, token) WHERE token <> '';
CREATE INDEX stepfunctions_tasks_execution ON stepfunctions_tasks(partition, account_id, region, execution_arn, frame_id);
CREATE INDEX stepfunctions_tasks_activity ON stepfunctions_tasks(partition, account_id, region, activity, scheduled, id) WHERE status = 'SCHEDULED';
CREATE INDEX stepfunctions_tasks_dispatch ON stepfunctions_tasks(scheduled, partition, account_id, region, execution_arn, frame_id, id) WHERE status = 'SCHEDULED' AND kind <> 'activity';
CREATE INDEX stepfunctions_tasks_timeout ON stepfunctions_tasks(deadline, partition, account_id, region, execution_arn, frame_id, id) WHERE status IN ('RUNNING', 'SUBMITTED') AND deadline IS NOT NULL;
CREATE INDEX stepfunctions_tasks_heartbeat ON stepfunctions_tasks(heartbeat_deadline, partition, account_id, region, execution_arn, frame_id, id) WHERE status IN ('RUNNING', 'SUBMITTED') AND heartbeat_deadline IS NOT NULL;
CREATE INDEX stepfunctions_tasks_recovery ON stepfunctions_tasks(id, partition, account_id, region) WHERE (status = 'RUNNING' AND kind <> 'activity') OR (status = 'SUBMITTED' AND kind = 'sync');

CREATE TABLE stepfunctions_history (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 event_id INTEGER NOT NULL,
 at DATETIME,
 event TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, execution_arn, event_id),
 FOREIGN KEY (partition, account_id, region, execution_arn)
 REFERENCES stepfunctions_executions(partition, account_id, region, arn) ON DELETE CASCADE
);
CREATE TABLE stepfunctions_map_runs (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 execution_arn TEXT NOT NULL,
 frame_id INTEGER NOT NULL,
 label TEXT NOT NULL,
 status TEXT NOT NULL,
 started DATETIME NOT NULL,
 stopped DATETIME,
 max_concurrency INTEGER NOT NULL,
 tolerated_failure_count INTEGER NOT NULL,
 tolerated_failure_percentage REAL NOT NULL,
 total_items INTEGER NOT NULL,
 results_written_items INTEGER NOT NULL,
 results_written_executions INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn),
 FOREIGN KEY (partition, account_id, region, execution_arn, frame_id)
 REFERENCES stepfunctions_frames(partition, account_id, region, execution_arn, id) ON DELETE CASCADE
);
CREATE INDEX stepfunctions_map_runs_execution ON stepfunctions_map_runs(partition, account_id, region, execution_arn, started DESC, arn);
