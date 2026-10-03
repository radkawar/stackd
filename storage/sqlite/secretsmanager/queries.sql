-- name: GetSecret :one
SELECT * FROM secretsmanager_secrets
WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListSecrets :many
SELECT * FROM secretsmanager_secrets
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: NextDeletion :one
SELECT * FROM secretsmanager_secrets WHERE delete_after IS NOT NULL
ORDER BY delete_after, arn LIMIT 1;

-- name: NextScheduledRotation :one
SELECT * FROM secretsmanager_secrets WHERE rotation_due IS NOT NULL AND deleted IS NULL
ORDER BY rotation_due, arn LIMIT 1;

-- name: PutSecret :exec
INSERT INTO secretsmanager_secrets (
 partition, account_id, region, name, arn, type, description, kms_key_id, owning_service,
 created, changed, last_accessed, deleted, delete_after, tags_present, policy_document,
 policy_principals_present, policy_trust, rotation_enabled, rotation_lambda_arn,
 last_rotated, next_rotation, rotation_due, primary_region
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, name) DO UPDATE SET
 arn = excluded.arn, type = excluded.type, description = excluded.description,
 kms_key_id = excluded.kms_key_id, owning_service = excluded.owning_service,
 created = excluded.created, changed = excluded.changed, last_accessed = excluded.last_accessed,
 deleted = excluded.deleted, delete_after = excluded.delete_after,
 tags_present = excluded.tags_present, policy_document = excluded.policy_document,
 policy_principals_present = excluded.policy_principals_present, policy_trust = excluded.policy_trust,
 rotation_enabled = excluded.rotation_enabled, rotation_lambda_arn = excluded.rotation_lambda_arn,
 last_rotated = excluded.last_rotated, next_rotation = excluded.next_rotation,
 rotation_due = excluded.rotation_due, primary_region = excluded.primary_region;

-- name: DeleteSecret :exec
DELETE FROM secretsmanager_secrets
WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListTags :many
SELECT key, value FROM secretsmanager_tags
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? ORDER BY key;

-- name: DeleteTags :exec
DELETE FROM secretsmanager_tags
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;

-- name: PutTag :exec
INSERT INTO secretsmanager_tags (partition, account_id, region, secret_name, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListPolicyPrincipals :many
SELECT arn, principal_id FROM secretsmanager_policy_principals
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? ORDER BY arn;

-- name: DeletePolicyPrincipals :exec
DELETE FROM secretsmanager_policy_principals
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;

-- name: PutPolicyPrincipal :exec
INSERT INTO secretsmanager_policy_principals (partition, account_id, region, secret_name, arn, principal_id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetRotationRules :one
SELECT * FROM secretsmanager_rotation_rules
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;

-- name: DeleteRotationRules :exec
DELETE FROM secretsmanager_rotation_rules
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;

-- name: PutRotationRules :exec
INSERT INTO secretsmanager_rotation_rules (
 partition, account_id, region, secret_name, automatically_after_days, duration, schedule_expression
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, secret_name) DO UPDATE SET
 automatically_after_days = excluded.automatically_after_days,
 duration = excluded.duration, schedule_expression = excluded.schedule_expression;

-- name: GetVersion :one
SELECT * FROM secretsmanager_versions
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND id = ?;

-- name: ListVersions :many
SELECT * FROM secretsmanager_versions
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? ORDER BY created, id;

-- name: PutVersion :exec
INSERT INTO secretsmanager_versions (
 partition, account_id, region, secret_name, id, binary, stages_present, created, last_accessed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, secret_name, id) DO UPDATE SET
 binary = excluded.binary, stages_present = excluded.stages_present,
 created = excluded.created, last_accessed = excluded.last_accessed;

-- name: DeleteVersion :exec
DELETE FROM secretsmanager_versions
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND id = ?;

-- name: ListVersionStages :many
SELECT stage FROM secretsmanager_version_stages
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?
ORDER BY position;

-- name: DeleteVersionStages :exec
DELETE FROM secretsmanager_version_stages
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?;

-- name: PutVersionStage :exec
INSERT INTO secretsmanager_version_stages (
 partition, account_id, region, secret_name, version_id, position, stage
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetEncryptedVersion :one
SELECT values_present FROM secretsmanager_encrypted_versions
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?;

-- name: PutEncryptedVersion :exec
INSERT INTO secretsmanager_encrypted_versions (
 partition, account_id, region, secret_name, version_id, values_present
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, secret_name, version_id) DO UPDATE SET
 values_present = excluded.values_present;

-- name: ListSealedValues :many
SELECT key_id, wrapped_key, payload FROM secretsmanager_sealed_values
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?
ORDER BY position;

-- name: ListVersionKeyIDs :many
SELECT key_id FROM secretsmanager_sealed_values
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?
ORDER BY position;

-- name: DeleteSealedValues :exec
DELETE FROM secretsmanager_sealed_values
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND version_id = ?;

-- name: PutSealedValue :exec
INSERT INTO secretsmanager_sealed_values (
 partition, account_id, region, secret_name, version_id, position, key_id, wrapped_key, payload
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetReplica :one
SELECT * FROM secretsmanager_replicas
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND replica_region = ?;

-- name: ListReplicas :many
SELECT * FROM secretsmanager_replicas
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? ORDER BY replica_region;

-- name: NextReplica :one
SELECT * FROM secretsmanager_replicas WHERE due IS NOT NULL
ORDER BY due, primary_arn || replica_region LIMIT 1;

-- name: PutReplica :exec
INSERT INTO secretsmanager_replicas (
 partition, account_id, region, secret_name, replica_region, primary_arn, kms_key_id,
 status, status_message, due
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, secret_name, replica_region) DO UPDATE SET
 primary_arn = excluded.primary_arn, kms_key_id = excluded.kms_key_id,
 status = excluded.status, status_message = excluded.status_message,
 due = excluded.due;

-- name: DeleteReplica :exec
DELETE FROM secretsmanager_replicas
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ? AND replica_region = ?;

-- name: GetRotation :one
SELECT * FROM secretsmanager_rotations
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;

-- name: NextRotationWork :one
SELECT * FROM secretsmanager_rotations WHERE due < deadline ORDER BY due, arn LIMIT 1;

-- name: PutRotation :exec
INSERT INTO secretsmanager_rotations (
 partition, account_id, region, secret_name, arn, token, invocation_token,
 step, attempt, test_only, due, deadline, last_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, secret_name) DO UPDATE SET
 arn = excluded.arn, token = excluded.token, invocation_token = excluded.invocation_token,
 step = excluded.step, attempt = excluded.attempt, test_only = excluded.test_only,
 due = excluded.due, deadline = excluded.deadline, last_error = excluded.last_error;

-- name: DeleteRotation :exec
DELETE FROM secretsmanager_rotations
WHERE partition = ? AND account_id = ? AND region = ? AND secret_name = ?;
