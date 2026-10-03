-- name: GetTopic :one
SELECT * FROM sns_topics WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListTopics :many
SELECT * FROM sns_topics WHERE partition = ? AND account_id = ? AND region = ? AND name > sqlc.arg(after_name) ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: CountTopics :one
SELECT COUNT(*) FROM sns_topics WHERE partition = ? AND account_id = ? AND region = ?;

-- name: GetTopicTags :many
SELECT key, value FROM sns_topic_tags WHERE topic_id = ? ORDER BY key;

-- name: GetTopicPrincipals :many
SELECT arn, principal_id FROM sns_topic_policy_principals WHERE topic_id = ? ORDER BY arn;

-- name: PutTopic :exec
INSERT INTO sns_topics (id, partition, account_id, region, name, created, updated, display_name, signature_version, policy, fifo, content_based_deduplication, fifo_throughput_scope, sequence, kms_master_key_id, delivery_policy, tracing_config)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET id=excluded.id, created=excluded.created, updated=excluded.updated, display_name=excluded.display_name, signature_version=excluded.signature_version, policy=excluded.policy, fifo=excluded.fifo, content_based_deduplication=excluded.content_based_deduplication, fifo_throughput_scope=excluded.fifo_throughput_scope, sequence=excluded.sequence, kms_master_key_id=excluded.kms_master_key_id, delivery_policy=excluded.delivery_policy, tracing_config=excluded.tracing_config;

-- name: DeleteTopic :exec
DELETE FROM sns_topics WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeleteTopicTags :exec
DELETE FROM sns_topic_tags WHERE topic_id = ?;

-- name: PutTopicTag :exec
INSERT INTO sns_topic_tags (topic_id, key, value) VALUES (?, ?, ?);

-- name: DeleteTopicPrincipals :exec
DELETE FROM sns_topic_policy_principals WHERE topic_id = ?;

-- name: PutTopicPrincipal :exec
INSERT INTO sns_topic_policy_principals (topic_id, arn, principal_id) VALUES (?, ?, ?);

-- name: GetTopicFeedback :many
SELECT protocol, success_role_arn, failure_role_arn, success_sample_rate
FROM sns_topic_feedback WHERE topic_id = ? ORDER BY protocol;

-- name: DeleteTopicFeedback :exec
DELETE FROM sns_topic_feedback WHERE topic_id = ?;

-- name: PutTopicFeedback :exec
INSERT INTO sns_topic_feedback (topic_id, protocol, success_role_arn, failure_role_arn, success_sample_rate)
VALUES (?, ?, ?, ?, ?);

-- name: GetSubscription :one
SELECT * FROM sns_subscriptions WHERE arn = ?;

-- name: GetSubscriptionByEndpoint :one
SELECT * FROM sns_subscriptions WHERE topic_id = ? AND protocol = ? AND endpoint = ? ORDER BY arn LIMIT 1;

-- name: GetConfirmation :one
SELECT token, expires, partition, account_id, region, topic_name, subscription_id FROM sns_confirmation_tokens WHERE token = ?;

-- name: PutConfirmation :exec
INSERT INTO sns_confirmation_tokens(token, partition, account_id, region, topic_name, subscription_id, expires) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DeleteExpiredConfirmations :exec
DELETE FROM sns_confirmation_tokens WHERE expires <= ?;

-- name: ListSubscriptionsByTopic :many
SELECT * FROM sns_subscriptions
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND topic_name = sqlc.arg(topic_name)
 AND (topic_id = sqlc.arg(topic_id) OR sqlc.arg(topic_id) = '') AND id > sqlc.arg(after_id)
ORDER BY id LIMIT sqlc.arg(page_limit);

-- name: ListSubscriptionsByOwner :many
SELECT s.* FROM sns_subscriptions s
JOIN sns_topics t ON t.id = s.topic_id AND t.partition = s.partition AND t.account_id = s.account_id AND t.region = s.region AND t.name = s.topic_name
WHERE s.partition = sqlc.arg(partition) AND s.region = sqlc.arg(region) AND s.owner = sqlc.arg(owner) AND s.arn > sqlc.arg(after_arn)
ORDER BY s.arn LIMIT sqlc.arg(page_limit);

-- name: CountSubscriptions :one
SELECT COUNT(*) FROM sns_subscriptions WHERE topic_id = ?;

-- name: CountTopicFilterPolicies :one
SELECT COUNT(*) FROM sns_subscriptions WHERE partition = ? AND region = ? AND topic_id = ? AND filter_policy NOT IN ('', '{}');

-- name: CountOwnerFilterPolicies :one
SELECT COUNT(*) FROM sns_subscriptions WHERE partition = ? AND region = ? AND owner = ? AND filter_policy NOT IN ('', '{}');

-- name: NextSubscriptionDeletion :one
SELECT arn, version, deletion_due FROM sns_subscriptions WHERE deletion_due IS NOT NULL ORDER BY deletion_due, arn LIMIT 1;

-- name: PutSubscription :exec
INSERT INTO sns_subscriptions (arn, partition, account_id, region, topic_name, id, topic_id, owner, principal_arn, protocol, endpoint, created, version, raw_message_delivery, filter_policy, filter_scope, redrive_arn, deletion_due, state, confirmation_authenticated, authenticate_on_unsubscribe, subscription_role_arn, delivery_policy, next_http_delivery, replay_policy, replay_status, replay_start, replay_end, replay_due, replay_cursor, replay_paused)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn) DO UPDATE SET topic_id=excluded.topic_id, owner=excluded.owner, principal_arn=excluded.principal_arn, protocol=excluded.protocol, endpoint=excluded.endpoint, created=excluded.created, version=excluded.version, raw_message_delivery=excluded.raw_message_delivery, filter_policy=excluded.filter_policy, filter_scope=excluded.filter_scope, redrive_arn=excluded.redrive_arn, deletion_due=excluded.deletion_due, state=excluded.state, confirmation_authenticated=excluded.confirmation_authenticated, authenticate_on_unsubscribe=excluded.authenticate_on_unsubscribe, subscription_role_arn=excluded.subscription_role_arn, delivery_policy=excluded.delivery_policy, next_http_delivery=excluded.next_http_delivery, replay_policy=excluded.replay_policy, replay_status=excluded.replay_status, replay_start=excluded.replay_start, replay_end=excluded.replay_end, replay_due=excluded.replay_due, replay_cursor=excluded.replay_cursor, replay_paused=excluded.replay_paused;

-- name: ListTopicSubscriptionVersions :many
SELECT arn, version FROM sns_subscriptions WHERE topic_id = ? ORDER BY id;

-- name: SetSubscriptionDeletion :exec
UPDATE sns_subscriptions SET deletion_due = ?, version = ? WHERE arn = ?;

-- name: DeleteSubscriptionDeliveries :many
DELETE FROM sns_deliveries WHERE subscription_arn = ? RETURNING message_id, message_protocol;

-- name: DeleteSubscription :exec
DELETE FROM sns_subscriptions WHERE arn = ?;

-- name: DeleteSubscriptionNotifications :many
DELETE FROM sns_deliveries WHERE subscription_arn = ?
AND EXISTS (SELECT 1 FROM sns_messages WHERE id = message_id AND protocol = message_protocol AND message_type = '')
RETURNING message_id, message_protocol;

-- name: GetMessage :one
SELECT * FROM sns_messages WHERE id = ? AND protocol = ?;

-- name: GetMessageAttributes :many
SELECT name, data_type, string_value, binary_value, CAST(binary_value IS NOT NULL AS INTEGER) AS has_binary_value FROM sns_message_attributes WHERE message_id = ? AND protocol = ? ORDER BY name;

-- name: GetMessageEncryptionContext :many
SELECT name, value FROM sns_message_encryption_context WHERE message_id = ? AND protocol = ? ORDER BY name;

-- name: DeleteMessageEncryptionContext :exec
DELETE FROM sns_message_encryption_context WHERE message_id = ? AND protocol = ?;

-- name: PutMessageEncryptionContext :exec
INSERT INTO sns_message_encryption_context (message_id, protocol, name, value) VALUES (?, ?, ?, ?);

-- name: PutMessage :exec
INSERT INTO sns_messages (id, protocol, partition, account_id, region, topic_name, body, subject, published, parent_event_id, request_id, signature_version, signature, signing_key_id, message_group_id, message_deduplication_id, sequence_number, structured, kms_key_arn, wrapped_data_key, encrypted_body, message_type, token, subscribe_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id, protocol) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, topic_name=excluded.topic_name, body=excluded.body, subject=excluded.subject, published=excluded.published, parent_event_id=excluded.parent_event_id, request_id=excluded.request_id, signature_version=excluded.signature_version, signature=excluded.signature, signing_key_id=excluded.signing_key_id, message_group_id=excluded.message_group_id, message_deduplication_id=excluded.message_deduplication_id, sequence_number=excluded.sequence_number, structured=excluded.structured, kms_key_arn=excluded.kms_key_arn, wrapped_data_key=excluded.wrapped_data_key, encrypted_body=excluded.encrypted_body, message_type=excluded.message_type, token=excluded.token, subscribe_url=excluded.subscribe_url;

-- name: DeleteMessageAttributes :exec
DELETE FROM sns_message_attributes WHERE message_id = ? AND protocol = ?;

-- name: PutMessageAttribute :exec
INSERT INTO sns_message_attributes (message_id, protocol, name, data_type, string_value, binary_value) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetDelivery :one
SELECT d.id, d.message_id, d.message_protocol, d.due, d.version, d.attempts, d.dead_letter, d.fifo_group, d.fifo_previous, d.replayed, s.partition, s.account_id, s.region, s.topic_name, s.id AS subscription_id
FROM sns_deliveries d JOIN sns_subscriptions s ON s.arn = d.subscription_arn WHERE d.id = ?;

-- name: NextDelivery :one
SELECT d.id, d.due, d.version FROM sns_deliveries d
WHERE d.dead_letter = TRUE OR NOT EXISTS (
 SELECT 1 FROM sns_deliveries p WHERE p.id = d.fifo_previous AND p.dead_letter = FALSE
)
ORDER BY d.due, d.id LIMIT 1;

-- name: DeliveryTail :one
SELECT d.id FROM sns_deliveries d
WHERE d.subscription_arn = ? AND d.fifo_group = ? AND d.dead_letter = FALSE
 AND NOT EXISTS (SELECT 1 FROM sns_deliveries n WHERE n.fifo_previous = d.id AND n.dead_letter = FALSE)
LIMIT 1;

-- name: PutDelivery :exec
INSERT INTO sns_deliveries (id, message_id, message_protocol, subscription_arn, due, version, attempts, dead_letter, fifo_group, fifo_previous, replayed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET subscription_arn=excluded.subscription_arn, due=excluded.due, version=excluded.version, attempts=excluded.attempts, dead_letter=excluded.dead_letter;

-- name: DeleteDelivery :one
DELETE FROM sns_deliveries WHERE id = ? RETURNING message_id, message_protocol;

-- name: CollectMessage :exec
DELETE FROM sns_messages
WHERE sns_messages.id = sqlc.arg(message_id) AND sns_messages.protocol = sqlc.arg(message_protocol)
 AND NOT EXISTS (SELECT 1 FROM sns_deliveries WHERE sns_deliveries.message_id = sqlc.arg(message_id) AND sns_deliveries.message_protocol = sqlc.arg(message_protocol))
 AND NOT EXISTS (SELECT 1 FROM sns_archive_entries WHERE sns_archive_entries.message_id = sqlc.arg(message_id) AND sns_archive_entries.message_protocol = sqlc.arg(message_protocol));

-- name: GetSigningKey :one
SELECT id, private_key_der, certificate_pem FROM sns_signing_key WHERE singleton = 1;

-- name: PutSigningKey :exec
INSERT INTO sns_signing_key (singleton, id, private_key_der, certificate_pem) VALUES (1, ?, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET id=excluded.id, private_key_der=excluded.private_key_der, certificate_pem=excluded.certificate_pem;

-- name: NextMetricPublication :one
SELECT partition, account_id, region, topic_name, minute FROM sns_metric_samples
ORDER BY minute, partition, account_id, region, topic_name LIMIT 1;

-- name: GetMetricSamples :many
SELECT metric_name, value, sample_count FROM sns_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND topic_name = ? AND minute = ?
ORDER BY metric_name, value;

-- name: AddMetricSample :exec
INSERT INTO sns_metric_samples (partition, account_id, region, topic_name, minute, metric_name, value, sample_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, topic_name, minute, metric_name, value) DO UPDATE SET
 sample_count=sns_metric_samples.sample_count+excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM sns_metric_samples
WHERE partition = ? AND account_id = ? AND region = ? AND topic_name = ? AND minute = ?;

-- name: GetDeduplication :one
SELECT message_id, sequence_number, expires FROM sns_deduplication
WHERE topic_id = ? AND message_group = ? AND deduplication_id = ?;

-- name: PutDeduplication :exec
INSERT INTO sns_deduplication (topic_id, message_group, deduplication_id, message_id, sequence_number, expires)
VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteExpiredDeduplication :exec
DELETE FROM sns_deduplication WHERE topic_id = ? AND expires <= ?;

-- name: NextTopicSequence :one
UPDATE sns_topics SET sequence = sequence + 1
WHERE partition = ? AND account_id = ? AND region = ? AND name = ?
RETURNING sequence;

-- name: GetTopicArchive :one
SELECT * FROM sns_topic_archives WHERE topic_id = ?;

-- name: PutTopicArchive :exec
INSERT INTO sns_topic_archives (topic_id, policy, retention_days, beginning, metric_due)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(topic_id) DO UPDATE SET policy=excluded.policy, retention_days=excluded.retention_days, beginning=excluded.beginning, metric_due=excluded.metric_due;

-- name: DeleteTopicArchive :exec
DELETE FROM sns_topic_archives WHERE topic_id = ?;

-- name: GetArchiveEntry :one
SELECT * FROM sns_archive_entries WHERE message_id = ? AND message_protocol = ?;

-- name: NextArchiveEntry :one
SELECT * FROM sns_archive_entries
WHERE topic_id = ? AND published >= sqlc.arg(start) AND sequence > sqlc.arg(after_sequence)
ORDER BY sequence, message_id, message_protocol LIMIT 1;

-- name: NextArchiveExpiration :one
SELECT * FROM sns_archive_entries ORDER BY expires, message_id, message_protocol LIMIT 1;

-- name: ArchiveUsage :one
SELECT COUNT(*) AS messages, CAST(COALESCE(SUM(size_bytes), 0) AS INTEGER) AS bytes
FROM sns_archive_entries WHERE topic_id = ?;

-- name: NextArchiveMetric :one
SELECT t.* FROM sns_topic_archives a JOIN sns_topics t ON t.id = a.topic_id
ORDER BY a.metric_due, 'arn:' || t.partition || ':sns:' || t.region || ':' || t.account_id || ':' || t.name LIMIT 1;

-- name: NextReplay :one
SELECT * FROM sns_subscriptions WHERE replay_policy <> '' AND replay_status IN ('Pending', 'In Progress')
ORDER BY replay_due, arn LIMIT 1;

-- name: PutArchiveEntry :exec
INSERT INTO sns_archive_entries (topic_id, message_id, message_protocol, published, expires, sequence, size_bytes)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(message_id, message_protocol) DO UPDATE SET topic_id=excluded.topic_id, published=excluded.published, expires=excluded.expires, sequence=excluded.sequence, size_bytes=excluded.size_bytes;

-- name: DeleteArchiveEntry :one
DELETE FROM sns_archive_entries WHERE message_id = ? AND message_protocol = ? RETURNING message_id, message_protocol;

-- name: DeleteArchiveEntries :many
DELETE FROM sns_archive_entries WHERE topic_id = ? RETURNING message_id, message_protocol;

-- name: ArchiveRetentionEntries :many
SELECT message_id, message_protocol, published, expires FROM sns_archive_entries WHERE topic_id = ?;

-- name: SetArchiveEntryExpiration :exec
UPDATE sns_archive_entries SET expires = ? WHERE message_id = ? AND message_protocol = ?;

