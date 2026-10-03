CREATE TABLE scheduler_groups (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 arn TEXT NOT NULL,
 created INTEGER NOT NULL,
 modified INTEGER NOT NULL,
 client_token TEXT NOT NULL,
 PRIMARY KEY (arn)
);

CREATE TABLE scheduler_schedules (
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 name TEXT NOT NULL,
 arn TEXT NOT NULL,
 created INTEGER NOT NULL,
 modified INTEGER NOT NULL,
 expression TEXT NOT NULL,
 timezone TEXT NOT NULL,
 state TEXT NOT NULL,
 description TEXT NOT NULL,
 has_description BOOLEAN NOT NULL,
 action_after_completion TEXT NOT NULL,
 start INTEGER,
 end INTEGER,
 next INTEGER,
 window_mode TEXT NOT NULL,
 window_minutes INTEGER NOT NULL,
 has_window_minutes BOOLEAN NOT NULL,
 kms_key_arn TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 data_key BLOB NOT NULL,
 revision INTEGER NOT NULL,
 create_token TEXT NOT NULL,
 update_token TEXT NOT NULL,
 create_hash TEXT NOT NULL,
 update_hash TEXT NOT NULL,
 PRIMARY KEY (arn)
);

CREATE TABLE scheduler_deliveries (
 id TEXT NOT NULL,
 partition TEXT NOT NULL,
 account TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 schedule_name TEXT NOT NULL,
 schedule_arn TEXT NOT NULL,
 revision INTEGER NOT NULL,
 scheduled INTEGER NOT NULL,
 due INTEGER NOT NULL,
 expires INTEGER NOT NULL,
 kms_key_arn TEXT NOT NULL,
 ciphertext BLOB NOT NULL,
 data_key BLOB NOT NULL,
 attempts INTEGER NOT NULL,
 phase TEXT NOT NULL,
 last_error_code TEXT NOT NULL,
 last_error_message TEXT NOT NULL,
 PRIMARY KEY (id)
);

CREATE TABLE scheduler_targets (
 owner_id TEXT NOT NULL,
 arn TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 input TEXT NOT NULL,
 dead_letter_arn TEXT NOT NULL,
 has_input BOOLEAN NOT NULL,
 max_age_seconds INTEGER NOT NULL,
 max_retries INTEGER NOT NULL,
 message_group_id TEXT NOT NULL,
 event_source TEXT NOT NULL,
 event_detail_type TEXT NOT NULL,
 partition_key TEXT NOT NULL,
 has_sqs BOOLEAN NOT NULL,
 has_event_bridge BOOLEAN NOT NULL,
 has_kinesis BOOLEAN NOT NULL,
 PRIMARY KEY (owner_id)
);

CREATE TABLE scheduler_ecs (
 owner_id TEXT NOT NULL,
 task_definition_arn TEXT NOT NULL,
 group_name TEXT NOT NULL,
 launch_type TEXT NOT NULL,
 platform_version TEXT NOT NULL,
 propagate_tags TEXT NOT NULL,
 reference_id TEXT NOT NULL,
 task_count INTEGER NOT NULL,
 has_task_count BOOLEAN NOT NULL,
 managed_tags BOOLEAN NOT NULL,
 execute_command BOOLEAN NOT NULL,
 has_managed_tags BOOLEAN NOT NULL,
 has_execute_command BOOLEAN NOT NULL,
 has_network BOOLEAN NOT NULL,
 assign_public_ip TEXT NOT NULL,
 PRIMARY KEY (owner_id),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_group_tags (
 group_arn TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (group_arn,key),
 FOREIGN KEY(group_arn) REFERENCES scheduler_groups(arn) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_subnets (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_security_groups (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_capacity (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 base INTEGER NOT NULL,
 weight INTEGER NOT NULL,
 has_base BOOLEAN NOT NULL,
 has_weight BOOLEAN NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_constraints (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 type TEXT NOT NULL,
 expression TEXT NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_placement (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 type TEXT NOT NULL,
 field TEXT NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE TABLE scheduler_ecs_tags (
 owner_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (owner_id,position),
 FOREIGN KEY(owner_id) REFERENCES scheduler_targets(owner_id) ON DELETE CASCADE
);

CREATE INDEX scheduler_schedules_due ON scheduler_schedules(next,arn) WHERE next IS NOT NULL;

CREATE INDEX scheduler_deliveries_due ON scheduler_deliveries(due,id);

CREATE INDEX scheduler_groups_scope ON scheduler_groups(partition,account,region,name);

CREATE INDEX scheduler_schedules_scope ON scheduler_schedules(partition,account,region,group_name,name);

CREATE INDEX scheduler_delivery_schedule ON scheduler_deliveries(schedule_arn);
