CREATE TABLE logs_subscriptions (
 group_id TEXT NOT NULL REFERENCES logs_groups(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 pattern TEXT NOT NULL,
 destination_arn TEXT NOT NULL,
 apply_on_transformed_logs INTEGER NOT NULL,
 distribution TEXT NOT NULL,
 field_selection TEXT NOT NULL,
 created INTEGER NOT NULL,
 disabled_until INTEGER NOT NULL,
 PRIMARY KEY (group_id, name)
);
CREATE TABLE logs_subscription_system_fields (
 subscription_id TEXT NOT NULL REFERENCES logs_subscriptions(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,
 field TEXT NOT NULL,
 PRIMARY KEY (subscription_id, ordinal)
);
CREATE TABLE logs_subscription_deliveries (
 id TEXT PRIMARY KEY,
 subscription_id TEXT NOT NULL REFERENCES logs_subscriptions(id) ON DELETE CASCADE,
 group_id TEXT NOT NULL,
 filter_name TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_name TEXT NOT NULL,
 destination_arn TEXT NOT NULL,
 parent_event_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 payload BLOB NOT NULL,
 due INTEGER NOT NULL,
 expires INTEGER NOT NULL,
 version INTEGER NOT NULL,
 attempts INTEGER NOT NULL
);
CREATE INDEX logs_subscription_deliveries_due ON logs_subscription_deliveries(due, id);
