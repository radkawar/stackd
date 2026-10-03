-- name: Request :one
SELECT * FROM cloudcontrol_requests WHERE token = ?;

-- name: Requests :many
SELECT * FROM cloudcontrol_requests
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY token;

-- name: NextRequest :one
SELECT * FROM cloudcontrol_requests
WHERE status IN ('PENDING', 'IN_PROGRESS', 'CANCEL_IN_PROGRESS')
ORDER BY due, token LIMIT 1;

-- name: PutRequest :exec
INSERT INTO cloudcontrol_requests (
    token, partition, account_id, region, client_token, request_hash, type_name,
    identifier, operation, status, phase, role_arn, desired, before_model, patch,
    model, error_code, message, caller_json, created, event_time, due, revision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(token) DO UPDATE SET
    identifier=excluded.identifier, status=excluded.status, phase=excluded.phase,
    desired=excluded.desired, before_model=excluded.before_model, model=excluded.model,
    error_code=excluded.error_code, message=excluded.message,
    event_time=excluded.event_time, due=excluded.due, revision=excluded.revision;
