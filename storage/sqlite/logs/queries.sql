-- name: GetGroup :one
SELECT * FROM logs_groups WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListGroups :many
SELECT * FROM logs_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND name > sqlc.arg(after_name) AND substr(name, 1, length(sqlc.arg(prefix))) = sqlc.arg(prefix)
 AND instr(name, sqlc.arg(contains_text)) > 0
 AND (sqlc.arg(class) = '' OR sqlc.arg(class) = 'STANDARD')
 ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: PutGroup :exec
INSERT INTO logs_groups (partition, account_id, region, name, id, created, sequence, retention_days, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 sequence=excluded.sequence, retention_days=excluded.retention_days, cfn_owner=excluded.cfn_owner;

-- name: DeleteGroup :exec
DELETE FROM logs_groups WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListTags :many
SELECT key, value FROM logs_tags WHERE group_id = ? ORDER BY key;
-- name: DeleteTags :exec
DELETE FROM logs_tags WHERE group_id = ?;
-- name: PutTag :exec
INSERT INTO logs_tags (group_id, key, value) VALUES (?, ?, ?);

-- name: GetStream :one
SELECT * FROM logs_streams WHERE group_id = ? AND name = ?;

-- name: ListStreamsByName :many
SELECT * FROM logs_streams WHERE group_id = sqlc.arg(group_id)
 AND substr(name,1,length(sqlc.arg(prefix))) = sqlc.arg(prefix)
 AND name > sqlc.arg(after_name) ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: ListStreamsByNameBackward :many
SELECT * FROM logs_streams WHERE group_id = sqlc.arg(group_id)
 AND substr(name,1,length(sqlc.arg(prefix))) = sqlc.arg(prefix)
 AND (sqlc.arg(after_name) = '' OR name < sqlc.arg(after_name)) ORDER BY name DESC LIMIT sqlc.arg(page_limit);

-- name: ListStreamsByTime :many
SELECT * FROM logs_streams WHERE group_id = sqlc.arg(group_id)
 AND (sqlc.arg(after_name) = '' OR (last_event, name) > (sqlc.arg(after_time), sqlc.arg(after_name)))
 ORDER BY last_event, name LIMIT sqlc.arg(page_limit);

-- name: ListStreamsByTimeBackward :many
SELECT * FROM logs_streams WHERE group_id = sqlc.arg(group_id)
 AND (sqlc.arg(after_name) = '' OR (last_event, name) < (sqlc.arg(after_time), sqlc.arg(after_name)))
 ORDER BY last_event DESC, name DESC LIMIT sqlc.arg(page_limit);

-- name: PutStream :exec
INSERT INTO logs_streams (group_id, name, id, created, first_event, last_event, last_ingestion, event_count, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(group_id, name) DO UPDATE SET first_event=excluded.first_event, last_event=excluded.last_event,
 last_ingestion=excluded.last_ingestion, event_count=excluded.event_count, cfn_owner=excluded.cfn_owner;

-- name: DeleteStream :exec
DELETE FROM logs_streams WHERE group_id = ? AND name = ?;

-- name: AppendEvent :exec
INSERT INTO logs_events (group_id, stream_id, stream_name, sequence, timestamp, ingestion, id, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GroupEventsForward :many
SELECT * FROM logs_events WHERE group_id = sqlc.arg(group_id)
 AND timestamp >= sqlc.arg(start_time) AND timestamp < sqlc.arg(end_time)
 AND (timestamp, ingestion, sequence) > (sqlc.arg(cursor_time), sqlc.arg(cursor_ingestion), sqlc.arg(cursor_sequence))
 ORDER BY timestamp, ingestion, sequence LIMIT sqlc.arg(page_limit);

-- name: GroupEventsBackward :many
SELECT * FROM logs_events WHERE group_id = sqlc.arg(group_id)
 AND timestamp >= sqlc.arg(start_time) AND timestamp < sqlc.arg(end_time)
 AND (timestamp, ingestion, sequence) < (sqlc.arg(cursor_time), sqlc.arg(cursor_ingestion), sqlc.arg(cursor_sequence))
 ORDER BY timestamp DESC, ingestion DESC, sequence DESC LIMIT sqlc.arg(page_limit);

-- name: StreamEventsForward :many
SELECT * FROM logs_events WHERE stream_id = sqlc.arg(stream_id)
 AND timestamp >= sqlc.arg(start_time) AND timestamp < sqlc.arg(end_time)
 AND (timestamp, ingestion, sequence) > (sqlc.arg(cursor_time), sqlc.arg(cursor_ingestion), sqlc.arg(cursor_sequence))
 ORDER BY timestamp, ingestion, sequence LIMIT sqlc.arg(page_limit);

-- name: StreamEventsBackward :many
SELECT * FROM logs_events WHERE stream_id = sqlc.arg(stream_id)
 AND timestamp >= sqlc.arg(start_time) AND timestamp < sqlc.arg(end_time)
 AND (timestamp, ingestion, sequence) < (sqlc.arg(cursor_time), sqlc.arg(cursor_ingestion), sqlc.arg(cursor_sequence))
 ORDER BY timestamp DESC, ingestion DESC, sequence DESC LIMIT sqlc.arg(page_limit);

-- name: StoredBytes :one
SELECT CAST(coalesce(sum(length(CAST(message AS BLOB))), 0) AS INTEGER) AS bytes
FROM logs_events WHERE group_id = ? AND timestamp >= ?;

-- name: GetResourcePolicy :one
SELECT * FROM logs_resource_policies
WHERE partition = ? AND account_id = ? AND region = ? AND policy_scope = ? AND name = ?;

-- name: ListResourcePolicies :many
SELECT * FROM logs_resource_policies
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND policy_scope = sqlc.arg(policy_scope) AND name > sqlc.arg(after_name)
 AND (sqlc.arg(resource_arn) = '' OR name = sqlc.arg(resource_arn))
ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: PutResourcePolicy :exec
INSERT INTO logs_resource_policies (partition, account_id, region, policy_scope, name, group_id, document, updated, revision, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, policy_scope, name) DO UPDATE SET
 group_id=excluded.group_id, document=excluded.document, updated=excluded.updated, revision=excluded.revision, cfn_owner=excluded.cfn_owner;

-- name: DeleteResourcePolicy :exec
DELETE FROM logs_resource_policies WHERE partition = ? AND account_id = ? AND region = ? AND policy_scope = ? AND name = ?;

-- name: GetSubscription :one
SELECT * FROM logs_subscriptions WHERE group_id = ? AND name = ?;

-- name: ListSubscriptions :many
SELECT * FROM logs_subscriptions WHERE group_id = sqlc.arg(group_id)
 AND name > sqlc.arg(after_name) AND substr(name, 1, length(sqlc.arg(prefix))) = sqlc.arg(prefix)
ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: PutSubscription :exec
INSERT INTO logs_subscriptions (group_id, name, id, pattern, destination_arn, apply_on_transformed_logs, distribution, field_selection, created, disabled_until,
 role_arn, target_arn, role_source_arn, sender_role_arn, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(group_id, name) DO UPDATE SET pattern=excluded.pattern, destination_arn=excluded.destination_arn,
 apply_on_transformed_logs=excluded.apply_on_transformed_logs, distribution=excluded.distribution, field_selection=excluded.field_selection,
 created=excluded.created, disabled_until=excluded.disabled_until,
 role_arn=excluded.role_arn, target_arn=excluded.target_arn, role_source_arn=excluded.role_source_arn, sender_role_arn=excluded.sender_role_arn, cfn_owner=excluded.cfn_owner;

-- name: DeleteSubscription :exec
DELETE FROM logs_subscriptions WHERE group_id = ? AND name = ?;

-- name: SubscriptionSystemFields :many
SELECT field FROM logs_subscription_system_fields WHERE subscription_id = ? ORDER BY ordinal;

-- name: DeleteSubscriptionSystemFields :exec
DELETE FROM logs_subscription_system_fields WHERE subscription_id = ?;

-- name: PutSubscriptionSystemField :exec
INSERT INTO logs_subscription_system_fields (subscription_id, ordinal, field) VALUES (?, ?, ?);

-- name: GetSubscriptionDelivery :one
SELECT * FROM logs_subscription_deliveries WHERE id = ?;

-- name: NextSubscriptionDelivery :one
SELECT id, due, version FROM logs_subscription_deliveries ORDER BY due, id LIMIT 1;

-- name: PutSubscriptionDelivery :exec
INSERT INTO logs_subscription_deliveries (id, subscription_id, group_id, filter_name, partition, account_id, region, group_name,
 destination_arn, parent_event_id, request_id, payload, due, expires, version, attempts,
 role_arn, target_arn, role_source_arn, partition_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET due=excluded.due, version=excluded.version, attempts=excluded.attempts;

-- name: DeleteSubscriptionDelivery :exec
DELETE FROM logs_subscription_deliveries WHERE id = ?;

-- name: GetDestination :one
SELECT * FROM logs_destinations WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListDestinations :many
SELECT * FROM logs_destinations
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region)
 AND name > sqlc.arg(after_name) AND substr(name, 1, length(sqlc.arg(prefix))) = sqlc.arg(prefix)
ORDER BY name LIMIT sqlc.arg(page_limit);

-- name: PutDestination :exec
INSERT INTO logs_destinations (partition, account_id, region, name, target_arn, role_arn, access_policy, created, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 target_arn=excluded.target_arn, role_arn=excluded.role_arn, access_policy=excluded.access_policy, cfn_owner=excluded.cfn_owner;

-- name: DeleteDestination :exec
DELETE FROM logs_destinations WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListDestinationTags :many
SELECT key, value FROM logs_destination_tags
WHERE partition = ? AND account_id = ? AND region = ? AND destination_name = ? ORDER BY key;

-- name: DeleteDestinationTags :exec
DELETE FROM logs_destination_tags WHERE partition = ? AND account_id = ? AND region = ? AND destination_name = ?;

-- name: PutDestinationTag :exec
INSERT INTO logs_destination_tags (partition, account_id, region, destination_name, key, value) VALUES (?, ?, ?, ?, ?, ?);
