CREATE TABLE sns_topics (
 id TEXT NOT NULL UNIQUE,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 updated TIMESTAMP NOT NULL,
 display_name TEXT NOT NULL,
 signature_version TEXT NOT NULL,
 policy TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE sns_topic_tags (
 topic_id TEXT NOT NULL REFERENCES sns_topics(id) ON DELETE CASCADE ON UPDATE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (topic_id, key)
);
CREATE TABLE sns_topic_policy_principals (
 topic_id TEXT NOT NULL REFERENCES sns_topics(id) ON DELETE CASCADE ON UPDATE CASCADE,
 arn TEXT NOT NULL,
 principal_id TEXT NOT NULL,
 PRIMARY KEY (topic_id, arn)
);
-- Membership deliberately has no foreign key to a live topic. Old incarnations
-- remain routable and addressable until the service's deletion deadline.
CREATE TABLE sns_subscriptions (
 arn TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 topic_name TEXT NOT NULL,
 id TEXT NOT NULL,
 topic_id TEXT NOT NULL,
 owner TEXT NOT NULL,
 principal_arn TEXT NOT NULL,
 protocol TEXT NOT NULL,
 endpoint TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 version BLOB NOT NULL CHECK (typeof(version) = 'blob' AND length(version) = 8),
 raw_message_delivery BOOLEAN NOT NULL,
 filter_policy TEXT NOT NULL,
 filter_scope TEXT NOT NULL,
 redrive_arn TEXT NOT NULL,
 deletion_due TIMESTAMP,
 UNIQUE (partition, account_id, region, topic_name, id)
);
CREATE INDEX sns_subscription_incarnation ON sns_subscriptions(topic_id, id);
CREATE INDEX sns_subscription_endpoint ON sns_subscriptions(topic_id, protocol, endpoint, arn);
CREATE INDEX sns_subscription_owner ON sns_subscriptions(partition, region, owner, arn);
CREATE INDEX sns_subscription_filter_topic ON sns_subscriptions(partition, region, topic_id) WHERE filter_policy NOT IN ('', '{}');
CREATE INDEX sns_subscription_filter_owner ON sns_subscriptions(partition, region, owner) WHERE filter_policy NOT IN ('', '{}');
CREATE INDEX sns_subscription_deletion ON sns_subscriptions(deletion_due, arn) WHERE deletion_due IS NOT NULL;
CREATE TABLE sns_messages (
 id TEXT NOT NULL,
 protocol TEXT NOT NULL,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 topic_name TEXT NOT NULL,
 body TEXT NOT NULL,
 subject TEXT,
 published TIMESTAMP NOT NULL,
 parent_event_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 signature_version TEXT NOT NULL,
 signature TEXT NOT NULL,
 signing_key_id TEXT NOT NULL,
 PRIMARY KEY (id, protocol)
);
CREATE TABLE sns_message_attributes (
 message_id TEXT NOT NULL,
 protocol TEXT NOT NULL,
 name TEXT NOT NULL,
 data_type TEXT,
 string_value TEXT,
 binary_value BLOB,
 PRIMARY KEY (message_id, protocol, name),
 FOREIGN KEY (message_id, protocol) REFERENCES sns_messages(id, protocol) ON DELETE CASCADE
);
CREATE TABLE sns_deliveries (
 id TEXT PRIMARY KEY,
 message_id TEXT NOT NULL,
 message_protocol TEXT NOT NULL,
 subscription_arn TEXT NOT NULL REFERENCES sns_subscriptions(arn),
 due TIMESTAMP NOT NULL,
 version BLOB NOT NULL CHECK (typeof(version) = 'blob' AND length(version) = 8),
 attempts INTEGER NOT NULL,
 dead_letter BOOLEAN NOT NULL,
 FOREIGN KEY (message_id, message_protocol) REFERENCES sns_messages(id, protocol)
);
CREATE INDEX sns_delivery_due ON sns_deliveries(due, id);
CREATE INDEX sns_delivery_subscription ON sns_deliveries(subscription_arn, id);
CREATE INDEX sns_delivery_message ON sns_deliveries(message_id, message_protocol);
CREATE TABLE sns_signing_key (
 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
 id TEXT NOT NULL,
 private_key_der BLOB NOT NULL,
 certificate_pem BLOB NOT NULL
);

-- Pending observations retain their original topic dimensions after deletion.
CREATE TABLE sns_metric_samples (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 topic_name TEXT NOT NULL,
 minute TIMESTAMP NOT NULL,
 metric_name TEXT NOT NULL,
 value INTEGER NOT NULL,
 sample_count INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, topic_name, minute, metric_name, value)
);
CREATE INDEX sns_metric_publication_due ON sns_metric_samples(minute, partition, account_id, region, topic_name);
