-- Sampling belongs to the queue, not to retained CloudWatch publications.
-- Older stores have no access history; use their last known mutation and let
-- the first sampler inspect retained messages before deciding inactivity.
ALTER TABLE sqs_queues ADD COLUMN metric_active_until TIMESTAMP;
ALTER TABLE sqs_queues ADD COLUMN next_metric_sample TIMESTAMP;
UPDATE sqs_queues SET metric_active_until = datetime(modified, '+6 hours'), next_metric_sample = modified;
CREATE INDEX sqs_queue_metric_deadlines ON sqs_queues (next_metric_sample, partition, account, region, name) WHERE next_metric_sample IS NOT NULL;

-- Age excludes initial delay and restarts on automatic DLQ transfer. An older
-- received source message no longer retains its initial availability time;
-- standard DLQ records also lack their transfer instant. Do not invent either.
ALTER TABLE sqs_messages ADD COLUMN age_started TIMESTAMP;
ALTER TABLE sqs_messages ADD COLUMN queue_receives INTEGER NOT NULL DEFAULT 0;
UPDATE sqs_messages SET queue_receives = receives WHERE source_arn = '';
UPDATE sqs_messages SET age_started = available WHERE source_arn = '' AND receives = 0;
UPDATE sqs_messages SET age_started = retention_started
WHERE source_arn != '' AND queue_id IN (SELECT id FROM sqs_queues WHERE fifo);
