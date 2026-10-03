CREATE TABLE cloudwatch_alarms (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 alarm_type TEXT NOT NULL,
 version INTEGER NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 description TEXT,
 actions_enabled BOOLEAN NOT NULL,
 state_value TEXT NOT NULL,
 state_reason TEXT,
 state_reason_data TEXT NOT NULL,
 state_updated TIMESTAMP NOT NULL,
 state_transitioned TIMESTAMP NOT NULL,
 state_event_id TEXT NOT NULL,
 state_request_id TEXT NOT NULL,
 next_evaluation TIMESTAMP,
 suppression_phase TEXT NOT NULL,
 suppression_reason TEXT NOT NULL,
 suppression_until TIMESTAMP,
 evaluation_event_id TEXT NOT NULL,
 evaluation_request_id TEXT NOT NULL,
 UNIQUE (partition, account_id, region, name)
);
CREATE INDEX cloudwatch_alarm_evaluation ON cloudwatch_alarms(
 CASE WHEN next_evaluation IS NULL THEN suppression_until
      WHEN suppression_until IS NULL THEN next_evaluation
      WHEN next_evaluation <= suppression_until THEN next_evaluation
      ELSE suppression_until END, id
) WHERE next_evaluation IS NOT NULL OR suppression_until IS NOT NULL;
CREATE TABLE cloudwatch_alarm_metric_configs (
 alarm_id TEXT PRIMARY KEY REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 query_id TEXT NOT NULL,
 comparison TEXT NOT NULL,
 threshold REAL NOT NULL,
 evaluation_periods INTEGER NOT NULL,
 datapoints_to_alarm INTEGER,
 treat_missing_data TEXT NOT NULL,
 low_sample_count TEXT NOT NULL
);
CREATE TABLE cloudwatch_alarm_queries (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 query_id TEXT NOT NULL,
 expression TEXT NOT NULL,
 account_id TEXT NOT NULL,
 label TEXT,
 period INTEGER,
 return_data BOOLEAN,
 PRIMARY KEY (alarm_id, position)
);
-- Position -1 is the scalar metric; other positions identify metric queries.
CREATE TABLE cloudwatch_alarm_metric_stats (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 namespace TEXT NOT NULL,
 name TEXT NOT NULL,
 dimensions TEXT NOT NULL,
 period INTEGER NOT NULL,
 statistic TEXT NOT NULL,
 unit TEXT NOT NULL,
 PRIMARY KEY (alarm_id, position)
);
CREATE TABLE cloudwatch_alarm_dimensions (
 alarm_id TEXT NOT NULL,
 metric_position INTEGER NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (alarm_id, metric_position, position),
 FOREIGN KEY (alarm_id, metric_position) REFERENCES cloudwatch_alarm_metric_stats(alarm_id, position) ON DELETE CASCADE
);
CREATE TABLE cloudwatch_alarm_composite_configs (
 alarm_id TEXT PRIMARY KEY REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 rule TEXT NOT NULL,
 suppressor TEXT NOT NULL,
 wait_period INTEGER NOT NULL,
 extension_period INTEGER NOT NULL
);
CREATE INDEX cloudwatch_alarm_suppressors ON cloudwatch_alarm_composite_configs(suppressor, alarm_id);
CREATE TABLE cloudwatch_alarm_children (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 PRIMARY KEY (alarm_id, position)
);
CREATE INDEX cloudwatch_alarm_parents ON cloudwatch_alarm_children(name, alarm_id);
CREATE TABLE cloudwatch_alarm_targets (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 state TEXT NOT NULL,
 position INTEGER NOT NULL,
 arn TEXT NOT NULL,
 PRIMARY KEY (alarm_id, state, position)
);
CREATE TABLE cloudwatch_alarm_tags (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (alarm_id, key)
);
-- History and accepted actions deliberately have no foreign key to live alarms.
CREATE TABLE cloudwatch_alarm_history (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 alarm_type TEXT NOT NULL,
 type TEXT NOT NULL,
 summary TEXT NOT NULL,
 at TIMESTAMP NOT NULL,
 data TEXT NOT NULL
);
CREATE INDEX cloudwatch_alarm_history_scope ON cloudwatch_alarm_history(partition, account_id, region, at, id);
CREATE INDEX cloudwatch_alarm_history_name ON cloudwatch_alarm_history(partition, account_id, region, name, at, id);
CREATE TABLE cloudwatch_alarm_actions (
 id TEXT PRIMARY KEY,
 event_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 alarm_type TEXT NOT NULL,
 target_arn TEXT NOT NULL,
 state TEXT NOT NULL,
 payload BLOB NOT NULL,
 accepted TIMESTAMP NOT NULL,
 due TIMESTAMP NOT NULL,
 version INTEGER NOT NULL,
 attempts INTEGER NOT NULL
);
CREATE INDEX cloudwatch_alarm_action_due ON cloudwatch_alarm_actions(due, id);
