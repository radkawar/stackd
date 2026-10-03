-- SQS owns queue configuration and every delivery record. Collection tables
-- preserve queue/message order; deleting a queue removes its delivery state.
CREATE TABLE sqs_queues (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    id TEXT NOT NULL UNIQUE,
    created TIMESTAMP NOT NULL,
    modified TIMESTAMP NOT NULL,
    purged TIMESTAMP NOT NULL,
    sequence BLOB NOT NULL,
    encryption_key BLOB,
    delay_seconds INTEGER NOT NULL,
    maximum_message_size INTEGER NOT NULL,
    retention_seconds INTEGER NOT NULL,
    visibility_seconds INTEGER NOT NULL,
    wait_seconds INTEGER NOT NULL,
    fifo BOOLEAN NOT NULL,
    content_deduplication BOOLEAN NOT NULL,
    managed_sse BOOLEAN NOT NULL,
    deduplication_scope TEXT NOT NULL,
    throughput TEXT NOT NULL,
    policy TEXT NOT NULL,
    kms_key TEXT NOT NULL,
    kms_reuse_seconds INTEGER NOT NULL,
    dead_letter_target_arn TEXT NOT NULL,
    max_receive_count INTEGER NOT NULL,
    redrive_permission TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);
CREATE TABLE sqs_queue_tags (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (queue_id, tag_key)
);
CREATE TABLE sqs_policy_principals (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    arn TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    PRIMARY KEY (queue_id, arn)
);
CREATE TABLE sqs_redrive_sources (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    arn TEXT NOT NULL,
    PRIMARY KEY (queue_id, position)
);
CREATE TABLE sqs_messages (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    message_group TEXT NOT NULL,
    deduplication_id TEXT NOT NULL,
    sequence TEXT NOT NULL,
    sender TEXT NOT NULL,
    data BLOB,
    encrypted BOOLEAN NOT NULL,
    kms_key_arn TEXT NOT NULL,
    encrypted_data_key BLOB,
    body_md5 TEXT NOT NULL,
    attributes_md5 TEXT NOT NULL,
    system_md5 TEXT NOT NULL,
    sent TIMESTAMP NOT NULL,
    retention_started TIMESTAMP NOT NULL,
    first_received TIMESTAMP NOT NULL,
    last_received TIMESTAMP NOT NULL,
    available TIMESTAMP NOT NULL,
    receives INTEGER NOT NULL,
    latest_receipt TEXT NOT NULL,
    generation BLOB NOT NULL,
    source_arn TEXT NOT NULL,
    PRIMARY KEY (queue_id, id),
    UNIQUE (queue_id, position)
);
-- Receipts and deduplication can outlive the message they identify.
CREATE TABLE sqs_receipts (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    handle TEXT NOT NULL,
    message_id TEXT NOT NULL,
    latest_receipt TEXT NOT NULL,
    expires TIMESTAMP NOT NULL,
    available TIMESTAMP NOT NULL,
    last_received TIMESTAMP NOT NULL,
    generation BLOB NOT NULL,
    PRIMARY KEY (queue_id, handle)
);
CREATE TABLE sqs_deduplications (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sequence TEXT NOT NULL,
    expires TIMESTAMP NOT NULL,
    PRIMARY KEY (queue_id, token)
);
CREATE TABLE sqs_receive_attempts (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires TIMESTAMP NOT NULL,
    PRIMARY KEY (queue_id, token)
);
CREATE TABLE sqs_receive_attempt_messages (
    queue_id TEXT NOT NULL,
    token TEXT NOT NULL,
    position INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    handle TEXT NOT NULL,
    generation BLOB NOT NULL,
    PRIMARY KEY (queue_id, token, position),
    FOREIGN KEY (queue_id, token) REFERENCES sqs_receive_attempts(queue_id, token) ON DELETE CASCADE
);
CREATE TABLE sqs_noisy_groups (
    queue_id TEXT NOT NULL REFERENCES sqs_queues(id) ON DELETE CASCADE,
    message_group TEXT NOT NULL,
    in_flight_until TIMESTAMP NOT NULL,
    PRIMARY KEY (queue_id, message_group)
);
CREATE TABLE sqs_deleted_queues (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    deleted_at TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);
-- Accepted tasks survive source deletion and retain their original caller.
CREATE TABLE sqs_move_tasks (
    handle TEXT PRIMARY KEY NOT NULL,
    sequence BLOB NOT NULL,
    source_partition TEXT NOT NULL,
    source_account TEXT NOT NULL,
    source_region TEXT NOT NULL,
    source_name TEXT NOT NULL,
    source_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    status TEXT NOT NULL,
    started TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL,
    rate INTEGER NOT NULL,
    custom_rate BOOLEAN NOT NULL,
    moved INTEGER NOT NULL,
    to_move INTEGER NOT NULL,
    failure TEXT NOT NULL,
    caller_account TEXT NOT NULL,
    caller_region TEXT NOT NULL,
    caller_partition TEXT NOT NULL,
    access_key_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    session_type TEXT NOT NULL,
    issuer_arn TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    has_session_policy BOOLEAN NOT NULL,
    federated_provider TEXT NOT NULL,
    source_identity TEXT NOT NULL,
    mfa_present BOOLEAN NOT NULL,
    mfa_authenticated_at TIMESTAMP NOT NULL,
    token_issue_time TIMESTAMP NOT NULL,
    transport_known BOOLEAN NOT NULL,
    source_ip TEXT NOT NULL,
    secure_transport BOOLEAN NOT NULL,
    user_agent TEXT NOT NULL
);
CREATE TABLE sqs_move_caller_lists (
    task_handle TEXT NOT NULL REFERENCES sqs_move_tasks(handle) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (task_handle, kind, position)
);
CREATE TABLE sqs_move_caller_tags (
    task_handle TEXT NOT NULL REFERENCES sqs_move_tasks(handle) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (task_handle, tag_key)
);
CREATE TABLE sqs_move_caller_context (
    task_handle TEXT NOT NULL REFERENCES sqs_move_tasks(handle) ON DELETE CASCADE,
    context_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (task_handle, context_key, position)
);
