CREATE TABLE cloudwatch_alarm_contributors (
 alarm_id TEXT NOT NULL REFERENCES cloudwatch_alarms(id) ON DELETE CASCADE,
 contributor_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 transitioned TIMESTAMP NOT NULL,
 PRIMARY KEY (alarm_id, contributor_id)
);
CREATE TABLE cloudwatch_alarm_contributor_attributes (
 alarm_id TEXT NOT NULL,
 contributor_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (alarm_id, contributor_id, key),
 FOREIGN KEY (alarm_id, contributor_id)
  REFERENCES cloudwatch_alarm_contributors(alarm_id, contributor_id) ON DELETE CASCADE
);

-- Captured identities belong to retained history/actions, never live alarms.
ALTER TABLE cloudwatch_alarm_history ADD COLUMN contributor_id TEXT;
CREATE INDEX cloudwatch_alarm_history_contributor ON cloudwatch_alarm_history(partition, account_id, region, contributor_id, at, id);
CREATE TABLE cloudwatch_alarm_history_contributor_attributes (
 history_id TEXT NOT NULL REFERENCES cloudwatch_alarm_history(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (history_id, key)
);

ALTER TABLE cloudwatch_alarm_actions ADD COLUMN contributor_id TEXT;
CREATE TABLE cloudwatch_alarm_action_contributor_attributes (
 action_id TEXT NOT NULL REFERENCES cloudwatch_alarm_actions(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (action_id, key)
);
