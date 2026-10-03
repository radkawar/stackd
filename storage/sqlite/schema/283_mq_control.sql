ALTER TABLE mq_brokers ADD COLUMN maintenance_day TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN maintenance_time TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN maintenance_zone TEXT NOT NULL DEFAULT '';
ALTER TABLE mq_brokers ADD COLUMN maintenance_due TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';

CREATE TABLE mq_broker_users (
 arn TEXT NOT NULL REFERENCES mq_brokers(arn) ON DELETE CASCADE,
 username TEXT NOT NULL,
 password TEXT NOT NULL,
 console_access BOOLEAN NOT NULL,
 pending_change TEXT NOT NULL,
 pending_password TEXT NOT NULL,
 pending_console_access BOOLEAN NOT NULL,
 PRIMARY KEY(arn,username)
);
CREATE TABLE mq_broker_user_groups (
 arn TEXT NOT NULL,
 username TEXT NOT NULL,
 pending BOOLEAN NOT NULL,
 group_name TEXT NOT NULL,
 PRIMARY KEY(arn,username,pending,group_name),
 FOREIGN KEY(arn,username) REFERENCES mq_broker_users(arn,username) ON DELETE CASCADE
);

-- Old controllers cleared the initial password after provisioning. An empty
-- password must not discard the retained native user or replace its credential.
INSERT INTO mq_broker_users(arn,username,password,console_access,pending_change,pending_password,pending_console_access)
SELECT arn,username,password,0,'','',0 FROM mq_brokers WHERE username<>'';

CREATE TABLE mq_configurations (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 arn TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 engine TEXT NOT NULL,
 engine_version TEXT NOT NULL,
 authentication_strategy TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 PRIMARY KEY(partition,account_id,region,id)
);
CREATE TABLE mq_configuration_tags (
 arn TEXT NOT NULL REFERENCES mq_configurations(arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL,
 tag_value TEXT NOT NULL,
 PRIMARY KEY(arn,tag_key)
);
CREATE TABLE mq_configuration_revisions (
 arn TEXT NOT NULL REFERENCES mq_configurations(arn) ON DELETE CASCADE,
 revision INTEGER NOT NULL,
 description TEXT NOT NULL,
 data TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 PRIMARY KEY(arn,revision)
);

-- References retain the exact admitted payload, independently of subsequent
-- configuration edits. History order is preserved, including repeated revisions.
CREATE TABLE mq_broker_configurations (
 arn TEXT NOT NULL REFERENCES mq_brokers(arn) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('current','pending','history')),
 position INTEGER NOT NULL,
 configuration_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 data TEXT NOT NULL,
 PRIMARY KEY(arn,kind,position)
);
