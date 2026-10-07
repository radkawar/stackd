-- name: GetUsagePlan :one
SELECT * FROM apigateway_usage_plans WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ?;

-- name: ListUsagePlans :many
SELECT * FROM apigateway_usage_plans WHERE partition = ? AND account_id = ? AND region = ? ORDER BY plan_id;

-- name: ListUsagePlansForKey :many
SELECT p.* FROM apigateway_usage_plans p JOIN apigateway_usage_plan_memberships m ON p.partition = m.partition AND p.account_id = m.account_id AND p.region = m.region AND p.plan_id = m.plan_id
WHERE m.partition = ? AND m.account_id = ? AND m.region = ? AND m.client_key_id = ? ORDER BY p.plan_id;

-- name: PutUsagePlan :exec
INSERT INTO apigateway_usage_plans (partition, account_id, region, plan_id, name, description, throttle_burst, throttle_rate, quota_limit, quota_offset, quota_period, cfn_stack_id, cfn_logical_id, cfn_incarnation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, plan_id) DO UPDATE SET name = excluded.name, description = excluded.description, throttle_burst = excluded.throttle_burst, throttle_rate = excluded.throttle_rate, quota_limit = excluded.quota_limit, quota_offset = excluded.quota_offset, quota_period = excluded.quota_period, cfn_stack_id = excluded.cfn_stack_id, cfn_logical_id = excluded.cfn_logical_id, cfn_incarnation = excluded.cfn_incarnation;

-- name: DeleteUsagePlan :exec
DELETE FROM apigateway_usage_plans WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ?;

-- name: ListUsagePlanTags :many
SELECT key, value FROM apigateway_usage_plan_tags WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? ORDER BY key;

-- name: PutUsagePlanTag :exec
INSERT INTO apigateway_usage_plan_tags (partition, account_id, region, plan_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteUsagePlanTags :exec
DELETE FROM apigateway_usage_plan_tags WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ?;

-- name: ListUsagePlanStages :many
SELECT * FROM apigateway_usage_plan_stages WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? ORDER BY ordinal;

-- name: PutUsagePlanStage :exec
INSERT INTO apigateway_usage_plan_stages (partition, account_id, region, plan_id, api_id, stage_name, ordinal, throttle_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteUsagePlanStages :exec
DELETE FROM apigateway_usage_plan_stages WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ?;

-- name: ListUsagePlanMethodThrottles :many
SELECT method_path, burst, rate FROM apigateway_usage_plan_method_throttles WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? AND api_id = ? AND stage_name = ? ORDER BY method_path;

-- name: PutUsagePlanMethodThrottle :exec
INSERT INTO apigateway_usage_plan_method_throttles (partition, account_id, region, plan_id, api_id, stage_name, method_path, burst, rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetUsagePlanMembership :one
SELECT * FROM apigateway_usage_plan_memberships WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? AND client_key_id = ?;

-- name: ListUsagePlanKeys :many
SELECT k.* FROM apigateway_client_keys k JOIN apigateway_usage_plan_memberships m ON k.partition = m.partition AND k.account_id = m.account_id AND k.region = m.region AND k.client_key_id = m.client_key_id
WHERE m.partition = ? AND m.account_id = ? AND m.region = ? AND m.plan_id = ? ORDER BY k.client_key_id;

-- name: PutUsagePlanMembership :exec
INSERT INTO apigateway_usage_plan_memberships (partition, account_id, region, plan_id, client_key_id, created, cfn_stack_id, cfn_logical_id, cfn_incarnation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, plan_id, client_key_id) DO UPDATE SET created = excluded.created, cfn_stack_id = excluded.cfn_stack_id, cfn_logical_id = excluded.cfn_logical_id, cfn_incarnation = excluded.cfn_incarnation;

-- name: DeleteUsagePlanMembership :exec
DELETE FROM apigateway_usage_plan_memberships WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? AND client_key_id = ?;

-- name: UsageCount :one
SELECT CAST(COALESCE(SUM(used), 0) AS INTEGER) FROM apigateway_usage_days WHERE partition = ? AND account_id = ? AND region = ? AND plan_id = ? AND client_key_id = ? AND day >= sqlc.arg(start) AND day < sqlc.arg(end);

-- name: IncrementUsage :exec
INSERT INTO apigateway_usage_days (partition, account_id, region, plan_id, client_key_id, day, used) VALUES (?, ?, ?, ?, ?, ?, 1)
ON CONFLICT (partition, account_id, region, plan_id, client_key_id, day) DO UPDATE SET used = apigateway_usage_days.used + 1;
