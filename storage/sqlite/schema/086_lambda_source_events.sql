ALTER TABLE lambda_sqs_batch_events RENAME TO lambda_source_batch_events;
ALTER TABLE lambda_source_batch_events RENAME COLUMN queue_arn TO source_arn;
ALTER TABLE lambda_sqs_batch_messages RENAME TO lambda_source_batch_records;
ALTER TABLE lambda_source_batch_records RENAME COLUMN message_id TO record_id;
UPDATE kernel_events SET event_type='lambda.source_batch.accepted.v1' WHERE event_type='lambda.sqs_batch.accepted.v1';
