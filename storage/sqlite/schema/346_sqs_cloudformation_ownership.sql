ALTER TABLE sqs_queues ADD COLUMN creation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE sqs_queues ADD COLUMN policy_owner TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX sqs_queue_creation_owner ON sqs_queues(partition, account, region, creation_owner) WHERE creation_owner <> '';
