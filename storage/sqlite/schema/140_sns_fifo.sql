ALTER TABLE sns_topics ADD COLUMN fifo BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sns_topics ADD COLUMN content_based_deduplication BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sns_topics ADD COLUMN fifo_throughput_scope TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_topics ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sns_messages ADD COLUMN message_deduplication_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN sequence_number TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_messages ADD COLUMN structured BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sns_deliveries ADD COLUMN fifo_group TEXT NOT NULL DEFAULT '';
ALTER TABLE sns_deliveries ADD COLUMN fifo_previous TEXT NOT NULL DEFAULT '';
CREATE INDEX sns_delivery_fifo_group ON sns_deliveries(subscription_arn, fifo_group) WHERE dead_letter = FALSE;
CREATE INDEX sns_delivery_fifo_previous ON sns_deliveries(fifo_previous) WHERE dead_letter = FALSE;
CREATE TABLE sns_deduplication (
 topic_id TEXT NOT NULL REFERENCES sns_topics(id) ON DELETE CASCADE,
 message_group TEXT NOT NULL,
 deduplication_id TEXT NOT NULL,
 message_id TEXT NOT NULL,
 sequence_number TEXT NOT NULL,
 expires TIMESTAMP NOT NULL,
 PRIMARY KEY (topic_id, message_group, deduplication_id)
);
CREATE INDEX sns_deduplication_expiry ON sns_deduplication(topic_id, expires);
