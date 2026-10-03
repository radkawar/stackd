-- name: GetQueue :one
SELECT * FROM sqs_queues WHERE partition = ? AND account = ? AND region = ? AND name = ?;

-- name: ListQueues :many
SELECT * FROM sqs_queues ORDER BY partition, region, account, name;

-- name: NextMetricQueue :one
SELECT * FROM sqs_queues WHERE next_metric_sample IS NOT NULL
ORDER BY next_metric_sample, partition, account, region, name LIMIT 1;

-- name: PutQueue :exec
INSERT INTO sqs_queues (partition, account, region, name, id, created, modified, purged, sequence, encryption_key, delay_seconds, maximum_message_size, retention_seconds, visibility_seconds, wait_seconds, fifo, content_deduplication, managed_sse, deduplication_scope, throughput, policy, kms_key, kms_reuse_seconds, dead_letter_target_arn, max_receive_count, redrive_permission, metric_active_until, next_metric_sample)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region, name) DO UPDATE SET
    id = excluded.id,
    created = excluded.created,
    modified = excluded.modified,
    purged = excluded.purged,
    metric_active_until = excluded.metric_active_until,
    next_metric_sample = excluded.next_metric_sample,
    sequence = excluded.sequence,
    encryption_key = excluded.encryption_key,
    delay_seconds = excluded.delay_seconds,
    maximum_message_size = excluded.maximum_message_size,
    retention_seconds = excluded.retention_seconds,
    visibility_seconds = excluded.visibility_seconds,
    wait_seconds = excluded.wait_seconds,
    fifo = excluded.fifo,
    content_deduplication = excluded.content_deduplication,
    managed_sse = excluded.managed_sse,
    deduplication_scope = excluded.deduplication_scope,
    throughput = excluded.throughput,
    policy = excluded.policy,
    kms_key = excluded.kms_key,
    kms_reuse_seconds = excluded.kms_reuse_seconds,
    dead_letter_target_arn = excluded.dead_letter_target_arn,
    max_receive_count = excluded.max_receive_count,
    redrive_permission = excluded.redrive_permission;

-- name: DeleteQueue :execrows
DELETE FROM sqs_queues WHERE partition = ? AND account = ? AND region = ? AND name = ?;

-- name: ListQueueTags :many
SELECT * FROM sqs_queue_tags WHERE queue_id = ? ORDER BY tag_key;

-- name: ClearQueueTags :exec
DELETE FROM sqs_queue_tags WHERE queue_id = ?;

-- name: InsertQueueTag :exec
INSERT INTO sqs_queue_tags (queue_id, tag_key, tag_value)
VALUES (?, ?, ?);

-- name: ListPolicyPrincipals :many
SELECT * FROM sqs_policy_principals WHERE queue_id = ? ORDER BY arn;

-- name: ClearPolicyPrincipals :exec
DELETE FROM sqs_policy_principals WHERE queue_id = ?;

-- name: InsertPolicyPrincipal :exec
INSERT INTO sqs_policy_principals (queue_id, arn, principal_id)
VALUES (?, ?, ?);

-- name: ListRedriveSources :many
SELECT * FROM sqs_redrive_sources WHERE queue_id = ? ORDER BY position;

-- name: ClearRedriveSources :exec
DELETE FROM sqs_redrive_sources WHERE queue_id = ?;

-- name: InsertRedriveSource :exec
INSERT INTO sqs_redrive_sources (queue_id, position, arn)
VALUES (?, ?, ?);

-- name: ListMessages :many
SELECT * FROM sqs_messages WHERE queue_id = ? ORDER BY position;

-- name: ClearMessages :exec
DELETE FROM sqs_messages WHERE queue_id = ?;

-- name: InsertMessage :exec
INSERT INTO sqs_messages (queue_id, position, id, message_group, deduplication_id, sequence, sender, data, encrypted, kms_key_arn, encrypted_data_key, body_md5, sent, retention_started, first_received, last_received, available, receives, latest_receipt, generation, source_arn, age_started, queue_receives)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListReceipts :many
SELECT * FROM sqs_receipts WHERE queue_id = ? ORDER BY handle;

-- name: ClearReceipts :exec
DELETE FROM sqs_receipts WHERE queue_id = ?;

-- name: InsertReceipt :exec
INSERT INTO sqs_receipts (queue_id, handle, message_id, latest_receipt, expires, available, last_received, generation)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListDeduplications :many
SELECT * FROM sqs_deduplications WHERE queue_id = ? ORDER BY token;

-- name: ClearDeduplications :exec
DELETE FROM sqs_deduplications WHERE queue_id = ?;

-- name: InsertDeduplication :exec
INSERT INTO sqs_deduplications (queue_id, token, message_id, sequence, expires)
VALUES (?, ?, ?, ?, ?);

-- name: ListReceiveAttempts :many
SELECT * FROM sqs_receive_attempts WHERE queue_id = ? ORDER BY token;

-- name: ClearReceiveAttempts :exec
DELETE FROM sqs_receive_attempts WHERE queue_id = ?;

-- name: InsertReceiveAttempt :exec
INSERT INTO sqs_receive_attempts (queue_id, token, expires)
VALUES (?, ?, ?);

-- name: ListReceiveAttemptMessages :many
SELECT * FROM sqs_receive_attempt_messages WHERE queue_id = ? ORDER BY token, position;

-- name: InsertReceiveAttemptMessage :exec
INSERT INTO sqs_receive_attempt_messages (queue_id, token, position, message_id, handle, generation)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListNoisyGroups :many
SELECT * FROM sqs_noisy_groups WHERE queue_id = ? ORDER BY message_group;

-- name: ClearNoisyGroups :exec
DELETE FROM sqs_noisy_groups WHERE queue_id = ?;

-- name: InsertNoisyGroup :exec
INSERT INTO sqs_noisy_groups (queue_id, message_group, in_flight_until)
VALUES (?, ?, ?);

-- name: GetDeletedQueue :one
SELECT deleted_at FROM sqs_deleted_queues WHERE partition = ? AND account = ? AND region = ? AND name = ?;

-- name: PutDeletedQueue :exec
INSERT INTO sqs_deleted_queues (partition, account, region, name, deleted_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region, name) DO UPDATE SET
    deleted_at = excluded.deleted_at;

-- name: ListMoveTasks :many
SELECT * FROM sqs_move_tasks ORDER BY sequence, handle;

-- name: PutMoveTask :exec
INSERT INTO sqs_move_tasks (handle, sequence, source_partition, source_account, source_region, source_name, source_id, destination, status, started, due, rate, custom_rate, moved, to_move, failure, caller_account, caller_region, caller_partition, access_key_id, request_id, principal_arn, principal_id, user_name, session_type, issuer_arn, issuer_id, has_session_policy, federated_provider, source_identity, mfa_present, mfa_authenticated_at, token_issue_time, transport_known, source_ip, secure_transport, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (handle) DO UPDATE SET
    sequence = excluded.sequence,
    source_partition = excluded.source_partition,
    source_account = excluded.source_account,
    source_region = excluded.source_region,
    source_name = excluded.source_name,
    source_id = excluded.source_id,
    destination = excluded.destination,
    status = excluded.status,
    started = excluded.started,
    due = excluded.due,
    rate = excluded.rate,
    custom_rate = excluded.custom_rate,
    moved = excluded.moved,
    to_move = excluded.to_move,
    failure = excluded.failure,
    caller_account = excluded.caller_account,
    caller_region = excluded.caller_region,
    caller_partition = excluded.caller_partition,
    access_key_id = excluded.access_key_id,
    request_id = excluded.request_id,
    principal_arn = excluded.principal_arn,
    principal_id = excluded.principal_id,
    user_name = excluded.user_name,
    session_type = excluded.session_type,
    issuer_arn = excluded.issuer_arn,
    issuer_id = excluded.issuer_id,
    has_session_policy = excluded.has_session_policy,
    federated_provider = excluded.federated_provider,
    source_identity = excluded.source_identity,
    mfa_present = excluded.mfa_present,
    mfa_authenticated_at = excluded.mfa_authenticated_at,
    token_issue_time = excluded.token_issue_time,
    transport_known = excluded.transport_known,
    source_ip = excluded.source_ip,
    secure_transport = excluded.secure_transport,
    user_agent = excluded.user_agent;

-- name: ListMoveCallerLists :many
SELECT * FROM sqs_move_caller_lists WHERE task_handle = ? ORDER BY kind, position;

-- name: ClearMoveCallerLists :exec
DELETE FROM sqs_move_caller_lists WHERE task_handle = ?;

-- name: InsertMoveCallerList :exec
INSERT INTO sqs_move_caller_lists (task_handle, kind, position, value)
VALUES (?, ?, ?, ?);

-- name: ListMoveCallerTags :many
SELECT * FROM sqs_move_caller_tags WHERE task_handle = ? ORDER BY tag_key;

-- name: ClearMoveCallerTags :exec
DELETE FROM sqs_move_caller_tags WHERE task_handle = ?;

-- name: InsertMoveCallerTag :exec
INSERT INTO sqs_move_caller_tags (task_handle, tag_key, tag_value)
VALUES (?, ?, ?);

-- name: ListMoveCallerContext :many
SELECT * FROM sqs_move_caller_context WHERE task_handle = ? ORDER BY context_key, position;

-- name: ClearMoveCallerContext :exec
DELETE FROM sqs_move_caller_context WHERE task_handle = ?;

-- name: InsertMoveCallerContext :exec
INSERT INTO sqs_move_caller_context (task_handle, context_key, position, value)
VALUES (?, ?, ?, ?);
