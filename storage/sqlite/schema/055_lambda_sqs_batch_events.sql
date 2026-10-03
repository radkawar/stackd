-- A batch can have several causal sends. Keep their message identities rather
-- than choosing one arbitrary parent or retaining another receipt/retry ledger.
CREATE TABLE lambda_sqs_batch_events (
    sequence INTEGER PRIMARY KEY REFERENCES kernel_events(sequence),
    invocation_event_id TEXT NOT NULL,
    mapping_arn TEXT NOT NULL,
    queue_arn TEXT NOT NULL
);
CREATE TABLE lambda_sqs_batch_messages (
    sequence INTEGER NOT NULL REFERENCES lambda_sqs_batch_events(sequence),
    ordinal INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY(sequence, ordinal)
);
