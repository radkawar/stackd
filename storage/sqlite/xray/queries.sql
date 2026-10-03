-- name: GetSegment :one
SELECT * FROM xray_segments
WHERE partition = ? AND account_id = ? AND region = ? AND trace_id = ? AND id = ?;

-- name: ListTraceSegments :many
SELECT * FROM xray_segments
WHERE partition = ? AND account_id = ? AND region = ? AND trace_id = ? ORDER BY id;

-- name: EarliestSegmentReceipt :one
SELECT received FROM xray_segments ORDER BY received LIMIT 1;

-- name: DeleteExpiredSegments :many
DELETE FROM xray_segments WHERE received <= ?
RETURNING partition, account_id, region, trace_id;

-- name: PutSegment :exec
INSERT INTO xray_segments (partition, account_id, region, trace_id, id, parent_id, subsegment, inline_order, start_time, end_time, in_progress, document, received, completed, received_revision, revision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, trace_id, id) DO UPDATE SET
 parent_id = excluded.parent_id, subsegment = excluded.subsegment,
 inline_order = excluded.inline_order,
 start_time = excluded.start_time, end_time = excluded.end_time, in_progress = excluded.in_progress,
 document = excluded.document, received = excluded.received, completed = excluded.completed,
 received_revision = excluded.received_revision, revision = excluded.revision;


-- name: ListResourcePolicies :many
SELECT * FROM xray_resource_policies
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: PutResourcePolicy :exec
INSERT INTO xray_resource_policies (partition, account_id, region, name, document, revision, updated)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 document = excluded.document, revision = excluded.revision, updated = excluded.updated;

-- name: DeleteResourcePolicy :exec
DELETE FROM xray_resource_policies WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetPolicyPrincipals :many
SELECT arn, principal_id FROM xray_policy_principals
WHERE partition = ? AND account_id = ? AND region = ? AND policy_name = ? ORDER BY arn;

-- name: DeletePolicyPrincipals :exec
DELETE FROM xray_policy_principals WHERE partition = ? AND account_id = ? AND region = ? AND policy_name = ?;

-- name: PutPolicyPrincipal :exec
INSERT INTO xray_policy_principals (partition, account_id, region, policy_name, arn, principal_id)
VALUES (?, ?, ?, ?, ?, ?);
