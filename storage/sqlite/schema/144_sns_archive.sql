CREATE TABLE sns_topic_archives (
 topic_id TEXT PRIMARY KEY REFERENCES sns_topics(id) ON DELETE CASCADE ON UPDATE CASCADE,
 policy TEXT NOT NULL,
 retention_days INTEGER NOT NULL,
 beginning TIMESTAMP NOT NULL,
 metric_due TIMESTAMP NOT NULL
);
CREATE INDEX sns_archive_metric_due ON sns_topic_archives(metric_due, topic_id);
CREATE TABLE sns_archive_entries (
 topic_id TEXT NOT NULL REFERENCES sns_topics(id) ON DELETE CASCADE ON UPDATE CASCADE,
 message_id TEXT NOT NULL,
 message_protocol TEXT NOT NULL,
 published TIMESTAMP NOT NULL,
 expires TIMESTAMP NOT NULL,
 sequence BLOB NOT NULL CHECK (typeof(sequence) = 'blob' AND length(sequence) = 8),
 size_bytes INTEGER NOT NULL,
 PRIMARY KEY (message_id, message_protocol),
 FOREIGN KEY (message_id, message_protocol) REFERENCES sns_messages(id, protocol)
);
CREATE INDEX sns_archive_topic_sequence ON sns_archive_entries(topic_id, sequence, message_id, message_protocol);
CREATE INDEX sns_archive_expiration ON sns_archive_entries(expires, message_id, message_protocol);
ALTER TABLE sns_subscriptions ADD COLUMN replay_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN replay_status TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_subscriptions ADD COLUMN replay_start TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE sns_subscriptions ADD COLUMN replay_end TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE sns_subscriptions ADD COLUMN replay_due TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
ALTER TABLE sns_subscriptions ADD COLUMN replay_cursor BLOB NOT NULL DEFAULT X'0000000000000000' CHECK (typeof(replay_cursor) = 'blob' AND length(replay_cursor) = 8);
ALTER TABLE sns_subscriptions ADD COLUMN replay_paused BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX sns_replay_due ON sns_subscriptions(replay_due, arn) WHERE replay_policy <> '' AND replay_status IN ('Pending', 'In Progress');
ALTER TABLE sns_deliveries ADD COLUMN replayed BOOLEAN NOT NULL DEFAULT FALSE;
