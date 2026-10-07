-- name: GetTrail :one
SELECT * FROM cloudtrail_trails WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: GetTrailByID :one
SELECT * FROM cloudtrail_trails WHERE id=?;
-- name: GetTrailByOwner :one
SELECT * FROM cloudtrail_trails WHERE partition=? AND region=? AND name=? AND cfn_owner=? AND cfn_owner<>'';
-- name: ListTrails :many
SELECT * FROM cloudtrail_trails WHERE partition=? AND account_id=? ORDER BY region, name;
-- name: FindOrganizationTrail :one
SELECT id FROM cloudtrail_trails WHERE partition=? AND organization_id<>'' LIMIT 1;
-- name: PutTrail :exec
INSERT INTO cloudtrail_trails(partition, account_id, region, name, id, bucket, prefix, include_global, multi_region, recursive_logging, logging, created, modified, started, stopped, stop_after, logs_group_arn, logs_role_arn, kms_key_id, sns_topic_name, organization_id, log_file_validation, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
bucket=excluded.bucket, prefix=excluded.prefix, include_global=excluded.include_global, multi_region=excluded.multi_region,
recursive_logging=excluded.recursive_logging, logging=excluded.logging, created=excluded.created, modified=excluded.modified, started=excluded.started, stopped=excluded.stopped, stop_after=excluded.stop_after,
logs_group_arn=excluded.logs_group_arn, logs_role_arn=excluded.logs_role_arn, kms_key_id=excluded.kms_key_id, sns_topic_name=excluded.sns_topic_name, organization_id=excluded.organization_id, log_file_validation=excluded.log_file_validation;
-- name: DeleteTrail :exec
DELETE FROM cloudtrail_trails WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: ListTags :many
SELECT * FROM cloudtrail_tags WHERE trail_id=? ORDER BY key;
-- name: PutTag :exec
INSERT INTO cloudtrail_tags(trail_id, key, value) VALUES (?, ?, ?);
-- name: DeleteTags :exec
DELETE FROM cloudtrail_tags WHERE trail_id=?;
-- name: ListBasicSelectors :many
SELECT * FROM cloudtrail_basic_selectors WHERE trail_id=? ORDER BY position;
-- name: PutBasicSelector :exec
INSERT INTO cloudtrail_basic_selectors(trail_id, position, read_only, include_management) VALUES (?, ?, ?, ?);
-- name: DeleteBasicSelectors :exec
DELETE FROM cloudtrail_basic_selectors WHERE trail_id=?;
-- name: ListExcludedSources :many
SELECT * FROM cloudtrail_excluded_sources WHERE trail_id=? ORDER BY selector_position, position;
-- name: PutExcludedSource :exec
INSERT INTO cloudtrail_excluded_sources(trail_id, selector_position, position, source) VALUES (?, ?, ?, ?);
-- name: ListDataResources :many
SELECT * FROM cloudtrail_data_resources WHERE trail_id=? ORDER BY selector_position, position;
-- name: PutDataResource :exec
INSERT INTO cloudtrail_data_resources(trail_id, selector_position, position, type) VALUES (?, ?, ?, ?);
-- name: ListDataPrefixes :many
SELECT * FROM cloudtrail_data_prefixes WHERE trail_id=? ORDER BY selector_position, resource_position, position;
-- name: PutDataPrefix :exec
INSERT INTO cloudtrail_data_prefixes(trail_id, selector_position, resource_position, position, prefix) VALUES (?, ?, ?, ?, ?);
-- name: ListAdvancedSelectors :many
SELECT * FROM cloudtrail_advanced_selectors WHERE trail_id=? ORDER BY position;
-- name: PutAdvancedSelector :exec
INSERT INTO cloudtrail_advanced_selectors(trail_id, position, name) VALUES (?, ?, ?);
-- name: DeleteAdvancedSelectors :exec
DELETE FROM cloudtrail_advanced_selectors WHERE trail_id=?;
-- name: ListFields :many
SELECT * FROM cloudtrail_fields WHERE trail_id=? ORDER BY selector_position, position;
-- name: PutField :exec
INSERT INTO cloudtrail_fields(trail_id, selector_position, position, field) VALUES (?, ?, ?, ?);
-- name: ListTests :many
SELECT * FROM cloudtrail_tests WHERE trail_id=? ORDER BY selector_position, field_position, position;
-- name: PutTest :exec
INSERT INTO cloudtrail_tests(trail_id, selector_position, field_position, position, operator) VALUES (?, ?, ?, ?, ?);
-- name: ListTestValues :many
SELECT * FROM cloudtrail_test_values WHERE trail_id=? ORDER BY selector_position, field_position, test_position, position;
-- name: PutTestValue :exec
INSERT INTO cloudtrail_test_values(trail_id, selector_position, field_position, test_position, position, value) VALUES (?, ?, ?, ?, ?, ?);
-- name: GetDeliveryStatus :one
SELECT * FROM cloudtrail_delivery_status WHERE trail_id=? AND destination=?;
-- name: PutDeliveryStatus :exec
INSERT INTO cloudtrail_delivery_status(trail_id, destination, last_attempt, last_success, last_error) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(trail_id, destination) DO UPDATE SET last_attempt=excluded.last_attempt, last_success=excluded.last_success, last_error=excluded.last_error;
-- name: DeleteDestinationStatus :exec
DELETE FROM cloudtrail_delivery_status WHERE trail_id=? AND destination=?;
-- name: DeleteDestinationDeliveries :exec
DELETE FROM cloudtrail_deliveries WHERE trail_id=? AND destination=?;
-- name: GetDelivery :one
SELECT * FROM cloudtrail_deliveries WHERE id=?;
-- name: OpenDelivery :one
SELECT * FROM cloudtrail_deliveries WHERE trail_id=? AND account_id=? AND region=? AND destination=? AND sealed=FALSE ORDER BY due, id LIMIT 1;
-- name: NextDelivery :one
SELECT id, due, version FROM cloudtrail_deliveries ORDER BY due, id LIMIT 1;
-- name: PutDelivery :exec
INSERT INTO cloudtrail_deliveries(id, trail_id, account_id, region, bucket, object_key, created, due, expires, sealed, event_count, attempts, version, destination, logs_group_arn, logs_role_arn, organization_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, region=excluded.region, bucket=excluded.bucket,
object_key=excluded.object_key, created=excluded.created, due=excluded.due, expires=excluded.expires, sealed=excluded.sealed,
event_count=excluded.event_count, attempts=excluded.attempts, version=excluded.version, destination=excluded.destination,
logs_group_arn=excluded.logs_group_arn, logs_role_arn=excluded.logs_role_arn, organization_id=excluded.organization_id;
-- name: ListDeliveryEventIDs :many
SELECT event_id FROM cloudtrail_delivery_events WHERE delivery_id=? ORDER BY position;
-- name: AppendDeliveryEvent :exec
INSERT INTO cloudtrail_delivery_events(delivery_id, position, event_id)
SELECT sqlc.arg(delivery_id), COALESCE(MAX(position), -1)+1, sqlc.arg(event_id) FROM cloudtrail_delivery_events WHERE delivery_id=sqlc.arg(delivery_id);
-- name: DeleteDelivery :exec
DELETE FROM cloudtrail_deliveries WHERE id=?;

-- name: ListDigestKeys :many
SELECT * FROM cloudtrail_digest_keys WHERE partition=? AND region=? ORDER BY start, fingerprint;
-- name: PutDigestKey :exec
INSERT INTO cloudtrail_digest_keys(partition,region,fingerprint,start,end,private_der,public_der) VALUES (?,?,?,?,?,?,?);
-- name: GetDigestStream :one
SELECT * FROM cloudtrail_digest_streams WHERE id=?;
-- name: ListDigestStreams :many
SELECT * FROM cloudtrail_digest_streams WHERE trail_id=? ORDER BY id;
-- name: NextDigest :one
SELECT * FROM cloudtrail_digest_streams ORDER BY due,id LIMIT 1;
-- name: PutDigestStream :exec
INSERT INTO cloudtrail_digest_streams(id,trail_id,partition,trail_account,home_region,trail_name,account_id,region,organization_id,bucket,prefix,kms_key_id,start,end,due,closed,closed_at,version,previous_bucket,previous_object,previous_hash,previous_signature,pending,pending_object,pending_hash,pending_signature)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET bucket=excluded.bucket,prefix=excluded.prefix,kms_key_id=excluded.kms_key_id,start=excluded.start,end=excluded.end,due=excluded.due,closed=excluded.closed,closed_at=excluded.closed_at,version=excluded.version,previous_bucket=excluded.previous_bucket,previous_object=excluded.previous_object,previous_hash=excluded.previous_hash,previous_signature=excluded.previous_signature,pending=excluded.pending,pending_object=excluded.pending_object,pending_hash=excluded.pending_hash,pending_signature=excluded.pending_signature;
-- name: DeleteDigestStream :exec
DELETE FROM cloudtrail_digest_streams WHERE id=?;
-- name: ListDigestLogs :many
SELECT * FROM cloudtrail_digest_logs WHERE stream_id=? AND delivered<? ORDER BY delivered,delivery_id;
-- name: PutDigestLog :exec
INSERT INTO cloudtrail_digest_logs(stream_id,delivery_id,bucket,object,hash,delivered,oldest,newest) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(stream_id,delivery_id) DO NOTHING;
-- name: DeleteDigestLogs :exec
DELETE FROM cloudtrail_digest_logs WHERE stream_id=? AND delivered<?;
-- name: GetDigestStatus :one
SELECT * FROM cloudtrail_digest_status WHERE trail_id=? AND account_id=? AND region=?;
-- name: PutDigestStatus :exec
INSERT INTO cloudtrail_digest_status(trail_id,account_id,region,last_attempt,last_success,last_error) VALUES (?,?,?,?,?,?)
ON CONFLICT(trail_id,account_id,region) DO UPDATE SET last_attempt=excluded.last_attempt,last_success=excluded.last_success,last_error=excluded.last_error;
