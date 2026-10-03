ALTER TABLE logs_subscriptions ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscriptions ADD COLUMN target_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscriptions ADD COLUMN role_source_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscriptions ADD COLUMN sender_role_arn TEXT NOT NULL DEFAULT '';

ALTER TABLE logs_subscription_deliveries ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscription_deliveries ADD COLUMN target_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscription_deliveries ADD COLUMN role_source_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE logs_subscription_deliveries ADD COLUMN partition_key TEXT NOT NULL DEFAULT '';

CREATE TABLE logs_destinations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 target_arn TEXT NOT NULL,
 role_arn TEXT NOT NULL,
 access_policy TEXT NOT NULL,
 created INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE logs_destination_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 destination_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, destination_name, key),
 FOREIGN KEY (partition, account_id, region, destination_name)
  REFERENCES logs_destinations(partition, account_id, region, name) ON DELETE CASCADE
);
