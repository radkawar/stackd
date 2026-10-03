-- Public optional values remain nullable; presence flags distinguish absent
-- nested configurations and collections from present-but-empty values.
CREATE TABLE aas_targets (
 target_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 namespace TEXT NOT NULL, resource_id TEXT NOT NULL, dimension TEXT NOT NULL,
 native_id TEXT NOT NULL, origin_event_id TEXT NOT NULL, reconcile_at TIMESTAMP,
 creation_time TIMESTAMP, max_capacity INTEGER, min_capacity INTEGER,
 predicted_capacity INTEGER, data_resource_id TEXT, role_arn TEXT,
 data_dimension TEXT, target_arn TEXT, data_namespace TEXT,
 has_suspended_state BOOLEAN NOT NULL,
 suspended_in BOOLEAN, suspended_out BOOLEAN, suspended_scheduled BOOLEAN,
 has_tags BOOLEAN NOT NULL,
 UNIQUE(partition, account_id, region, namespace, resource_id, dimension)
);
CREATE INDEX aas_targets_arn ON aas_targets(partition, account_id, region, target_arn);
CREATE INDEX aas_targets_due ON aas_targets(reconcile_at, partition, account_id, region, namespace, resource_id, dimension) WHERE reconcile_at IS NOT NULL;
CREATE TABLE aas_target_tags (
 target_pk INTEGER NOT NULL REFERENCES aas_targets(target_pk) ON DELETE CASCADE,
 key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(target_pk, key)
);

-- Source-key deletion is explicit in the adapter: like the memory repository,
-- policy/action rows can be written independently of a target row. Their typed
-- child rows cascade from the policy's durable local identity.
CREATE TABLE aas_policies (
 policy_pk INTEGER PRIMARY KEY,
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 namespace TEXT NOT NULL, resource_id TEXT NOT NULL, dimension TEXT NOT NULL, name TEXT NOT NULL,
 managed_action_id TEXT NOT NULL, last_scale_at TIMESTAMP NOT NULL,
 last_scale_from INTEGER NOT NULL, last_scale_to INTEGER NOT NULL,
 pending_scale_at TIMESTAMP NOT NULL,
 pending_scale_from INTEGER NOT NULL, pending_scale_to INTEGER NOT NULL,
 creation_time TIMESTAMP, policy_arn TEXT, policy_name TEXT, policy_type TEXT,
 data_resource_id TEXT, data_dimension TEXT, data_namespace TEXT,
 has_alarms BOOLEAN NOT NULL,
 has_step BOOLEAN NOT NULL, step_adjustment_type TEXT, step_cooldown INTEGER,
 step_aggregation_type TEXT, step_min_adjustment INTEGER, has_steps BOOLEAN NOT NULL,
 has_tracking BOOLEAN NOT NULL, disable_scale_in BOOLEAN,
 scale_in_cooldown INTEGER, scale_out_cooldown INTEGER, target_value REAL,
 has_predefined BOOLEAN NOT NULL, predefined_metric_type TEXT, resource_label TEXT,
 has_custom BOOLEAN NOT NULL, custom_metric_name TEXT, custom_namespace TEXT,
 custom_statistic TEXT, custom_unit TEXT,
 has_custom_dimensions BOOLEAN NOT NULL, has_metric_queries BOOLEAN NOT NULL,
 UNIQUE(partition, account_id, region, namespace, resource_id, dimension, name)
);
CREATE TABLE aas_policy_alarms (
 policy_pk INTEGER NOT NULL REFERENCES aas_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL, alarm_arn TEXT, alarm_name TEXT,
 PRIMARY KEY(policy_pk, position)
);
CREATE TABLE aas_policy_steps (
 policy_pk INTEGER NOT NULL REFERENCES aas_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL, lower_bound REAL, upper_bound REAL, adjustment INTEGER,
 PRIMARY KEY(policy_pk, position)
);
CREATE TABLE aas_policy_metric_queries (
 policy_pk INTEGER NOT NULL REFERENCES aas_policies(policy_pk) ON DELETE CASCADE,
 position INTEGER NOT NULL, expression TEXT, query_id TEXT, label TEXT, return_data BOOLEAN,
 has_stat BOOLEAN NOT NULL, stat TEXT, unit TEXT,
 has_metric BOOLEAN NOT NULL, metric_name TEXT, namespace TEXT, has_dimensions BOOLEAN NOT NULL,
 PRIMARY KEY(policy_pk, position)
);
-- metric_position -1 is the simple custom metric; other positions identify
-- metric-math query metrics. Positions preserve caller dimension order.
CREATE TABLE aas_policy_dimensions (
 policy_pk INTEGER NOT NULL REFERENCES aas_policies(policy_pk) ON DELETE CASCADE,
 metric_position INTEGER NOT NULL, position INTEGER NOT NULL, name TEXT, value TEXT,
 PRIMARY KEY(policy_pk, metric_position, position)
);
CREATE TABLE aas_schedules (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 namespace TEXT NOT NULL, resource_id TEXT NOT NULL, dimension TEXT NOT NULL, name TEXT NOT NULL,
 origin_event_id TEXT NOT NULL, next_due TIMESTAMP,
 creation_time TIMESTAMP, start_time TIMESTAMP, end_time TIMESTAMP, timezone TEXT,
 data_resource_id TEXT, data_dimension TEXT, data_namespace TEXT,
 schedule TEXT, action_arn TEXT, action_name TEXT,
 has_action BOOLEAN NOT NULL, max_capacity INTEGER, min_capacity INTEGER,
 PRIMARY KEY(partition, account_id, region, namespace, resource_id, dimension, name)
);
CREATE INDEX aas_schedules_due ON aas_schedules(next_due, partition, account_id, region, namespace, resource_id, dimension, name) WHERE next_due IS NOT NULL;
