-- name: ListMemberships :many
SELECT service, arn FROM resourcegroupstaggingapi_memberships
WHERE partition = ? AND account_id = ? AND region = ?
  AND (CAST(sqlc.arg(service_filter) AS TEXT) = '' OR service = sqlc.arg(service_filter))
ORDER BY arn, service;

-- name: PutMembership :exec
INSERT INTO resourcegroupstaggingapi_memberships (partition, account_id, region, service, arn)
VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING;

-- name: DeleteMembership :exec
DELETE FROM resourcegroupstaggingapi_memberships
WHERE partition = ? AND account_id = ? AND region = ? AND service = ? AND arn = ?;

-- name: GetReport :one
SELECT * FROM resourcegroupstaggingapi_reports
WHERE partition = ? AND account_id = ? AND region = ?;

-- name: NextReport :one
SELECT * FROM resourcegroupstaggingapi_reports
WHERE status = 'RUNNING'
ORDER BY due, partition, account_id, region
LIMIT 1;

-- name: PutReport :exec
INSERT INTO resourcegroupstaggingapi_reports (
    partition, account_id, region, version, organization_id, bucket, object_key,
    status, error_message, started_at, completed_at, due, caller_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET
    version = excluded.version, organization_id = excluded.organization_id,
    bucket = excluded.bucket, object_key = excluded.object_key,
    status = excluded.status, error_message = excluded.error_message,
    started_at = excluded.started_at, completed_at = excluded.completed_at,
    due = excluded.due, caller_json = excluded.caller_json;
