-- name: GetSamplingRule :one
SELECT * FROM xray_sampling_rules WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListSamplingRules :many
SELECT * FROM xray_sampling_rules WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: PutSamplingRule :exec
INSERT INTO xray_sampling_rules (partition, account_id, region, name, priority, fixed_rate, reservoir_size, host, http_method, resource_arn, service_name, service_type, url_path, boost_max_rate, boost_cooldown_minutes, created, modified, cfn_owner)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET
 priority = excluded.priority,
 fixed_rate = excluded.fixed_rate,
 reservoir_size = excluded.reservoir_size,
 host = excluded.host,
 http_method = excluded.http_method,
 resource_arn = excluded.resource_arn,
 service_name = excluded.service_name,
 service_type = excluded.service_type,
 url_path = excluded.url_path,
 boost_max_rate = excluded.boost_max_rate,
 boost_cooldown_minutes = excluded.boost_cooldown_minutes,
 created = excluded.created,
 modified = excluded.modified,
 cfn_owner = excluded.cfn_owner;

-- name: DeleteSamplingRule :exec
DELETE FROM xray_sampling_rules WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListSamplingAttributes :many
SELECT key, value FROM xray_sampling_attributes WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ? ORDER BY key;

-- name: DeleteSamplingAttributes :exec
DELETE FROM xray_sampling_attributes WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: PutSamplingAttribute :exec
INSERT INTO xray_sampling_attributes (partition, account_id, region, rule_name, key, value)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, key) DO UPDATE SET
 value = excluded.value;

-- name: ListSamplingTags :many
SELECT key, value FROM xray_sampling_tags WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ? ORDER BY key;

-- name: DeleteSamplingTags :exec
DELETE FROM xray_sampling_tags WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: PutSamplingTag :exec
INSERT INTO xray_sampling_tags (partition, account_id, region, rule_name, key, value)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, key) DO UPDATE SET
 value = excluded.value;

-- name: ListSamplingClients :many
SELECT * FROM xray_sampling_clients WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ? ORDER BY client_id;

-- name: PutSamplingClient :exec
INSERT INTO xray_sampling_clients (partition, account_id, region, rule_name, client_id, first_seen, last_seen, quota, quota_expires)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, client_id) DO UPDATE SET
 first_seen = excluded.first_seen,
 last_seen = excluded.last_seen,
 quota = excluded.quota,
 quota_expires = excluded.quota_expires;

-- name: DeleteSamplingClients :exec
DELETE FROM xray_sampling_clients WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: DeleteExpiredSamplingClients :exec
DELETE FROM xray_sampling_clients WHERE last_seen <= ?;

-- name: ListSamplingStatistics :many
SELECT * FROM xray_sampling_statistics WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ? ORDER BY window, client_id;

-- name: PutSamplingStatistic :exec
INSERT INTO xray_sampling_statistics (partition, account_id, region, rule_name, client_id, window, timestamp, received, request_count, sampled_count, borrow_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, client_id, window) DO UPDATE SET
 timestamp = excluded.timestamp,
 received = excluded.received,
 request_count = excluded.request_count,
 sampled_count = excluded.sampled_count,
 borrow_count = excluded.borrow_count;

-- name: DeleteSamplingStatistics :exec
DELETE FROM xray_sampling_statistics WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: DeleteExpiredSamplingStatistics :exec
DELETE FROM xray_sampling_statistics WHERE received <= ?;

-- name: ListSamplingBoostStatistics :many
SELECT * FROM xray_sampling_boost_statistics WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ? ORDER BY window, service_name;

-- name: PutSamplingBoostStatistic :exec
INSERT INTO xray_sampling_boost_statistics (partition, account_id, region, rule_name, service_name, window, timestamp, received, total_count, anomaly_count, sampled_anomaly_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, service_name, window) DO UPDATE SET
 timestamp = excluded.timestamp,
 received = excluded.received,
 total_count = excluded.total_count,
 anomaly_count = excluded.anomaly_count,
 sampled_anomaly_count = excluded.sampled_anomaly_count;

-- name: DeleteSamplingBoostStatistics :exec
DELETE FROM xray_sampling_boost_statistics WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: DeleteExpiredSamplingBoostStatistics :exec
DELETE FROM xray_sampling_boost_statistics WHERE received <= ?;

-- name: GetSamplingBoost :one
SELECT * FROM xray_sampling_boosts WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: PutSamplingBoost :exec
INSERT INTO xray_sampling_boosts (partition, account_id, region, rule_name, rate, expires, triggered)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name) DO UPDATE SET
 rate = excluded.rate,
 expires = excluded.expires,
 triggered = excluded.triggered;

-- name: DeleteSamplingBoost :exec
DELETE FROM xray_sampling_boosts WHERE partition = ? AND account_id = ? AND region = ? AND rule_name = ?;

-- name: GetSamplingModified :one
SELECT modified FROM xray_sampling_modifications WHERE partition = ? AND account_id = ? AND region = ?;

-- name: SetSamplingModified :exec
INSERT INTO xray_sampling_modifications (partition, account_id, region, modified)
VALUES (?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET
 modified = excluded.modified;

-- name: EarliestSamplingReceipt :one
SELECT receipt FROM (
 SELECT received AS receipt FROM xray_sampling_statistics
 UNION ALL SELECT last_seen AS receipt FROM xray_sampling_clients
 UNION ALL SELECT received AS receipt FROM xray_sampling_boost_statistics
) ORDER BY receipt LIMIT 1;

-- name: ListScopeSamplingAttributes :many
SELECT * FROM xray_sampling_attributes
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY rule_name, key;

-- name: ListScopeSamplingTags :many
SELECT * FROM xray_sampling_tags
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY rule_name, key;
