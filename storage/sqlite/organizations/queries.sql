-- name: GetPartition :one
SELECT * FROM org_partitions WHERE partition = ?;

-- name: PutPartitions :exec
INSERT INTO org_partitions (partition, revision, account_sequence)
VALUES (?, ?, ?);

-- name: Partitions :many
SELECT partition FROM org_partitions ORDER BY partition;

-- name: DeletePartition :exec
DELETE FROM org_partitions WHERE partition = ?;

-- name: Registry :many
SELECT * FROM org_registry WHERE partition = ? ORDER BY position;

-- name: PutRegistry :exec
INSERT INTO org_registry (partition, position, id, arn, name, email, status, state, joined_method, joined_timestamp)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: Organizations :many
SELECT * FROM org_organizations WHERE partition = ? ORDER BY position;

-- name: PutOrganizations :exec
INSERT INTO org_organizations (partition, org_id, position, arn, feature_set, master_account_id, master_account_arn, master_account_email, root_id, root_arn, root_name, credentials_management, root_sessions)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: AvailablePolicyTypes :many
SELECT * FROM org_available_policy_types WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutAvailablePolicyTypes :exec
INSERT INTO org_available_policy_types (partition, org_id, position, type, status)
VALUES (?, ?, ?, ?, ?);

-- name: RootPolicyTypes :many
SELECT * FROM org_root_policy_types WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutRootPolicyTypes :exec
INSERT INTO org_root_policy_types (partition, org_id, position, type, status)
VALUES (?, ?, ?, ?, ?);

-- name: Members :many
SELECT * FROM org_members WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutMembers :exec
INSERT INTO org_members (partition, org_id, position, id, arn, name, email, status, state, joined_method, joined_timestamp)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: Units :many
SELECT * FROM org_units WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutUnits :exec
INSERT INTO org_units (partition, org_id, position, id, arn, name)
VALUES (?, ?, ?, ?, ?, ?);

-- name: Parents :many
SELECT * FROM org_parents WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutParents :exec
INSERT INTO org_parents (partition, org_id, position, child_id, parent_id)
VALUES (?, ?, ?, ?, ?);

-- name: Creations :many
SELECT * FROM org_creations WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutCreations :exec
INSERT INTO org_creations (partition, org_id, position, id, account_id, account_name, email, role_name, state, failure_reason, requested_at, due, completed_at, request_id, request_region, actor_arn)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: Policies :many
SELECT * FROM org_policies WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutPolicies :exec
INSERT INTO org_policies (partition, org_id, position, id, arn, name, description, type, content, aws_managed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: Attachments :many
SELECT * FROM org_attachments WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutAttachments :exec
INSERT INTO org_attachments (partition, org_id, position, target_id, policy_id)
VALUES (?, ?, ?, ?, ?);

-- name: Tags :many
SELECT * FROM org_tags WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutTags :exec
INSERT INTO org_tags (partition, org_id, position, resource_id, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: Services :many
SELECT * FROM org_services WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutServices :exec
INSERT INTO org_services (partition, org_id, position, principal, enabled)
VALUES (?, ?, ?, ?, ?);

-- name: Delegations :many
SELECT * FROM org_delegations WHERE partition = ? AND org_id = ? ORDER BY position;

-- name: PutDelegations :exec
INSERT INTO org_delegations (partition, org_id, position, account_id, principal, enabled)
VALUES (?, ?, ?, ?, ?, ?);

-- name: CreationTags :many
SELECT * FROM org_creation_tags WHERE partition = ? AND org_id = ? AND creation_position = ? ORDER BY key;

-- name: PutCreationTags :exec
INSERT INTO org_creation_tags (partition, org_id, creation_position, key, value)
VALUES (?, ?, ?, ?, ?);

-- name: ResourcePolicy :one
SELECT id, arn, content FROM org_resource_policies WHERE partition = ? AND org_id = ?;

-- name: PutResourcePolicy :exec
INSERT INTO org_resource_policies (partition, org_id, id, arn, content) VALUES (?, ?, ?, ?, ?);

-- name: Handshakes :many
SELECT * FROM org_handshakes WHERE partition = ? ORDER BY id;

-- name: PutHandshake :exec
INSERT INTO org_handshakes (action, parent_id, partition, id, organization_id, management_account_id, management_name, management_email, feature_set, target_account_id, target_type, target, notes, state, requested_at, expires_at, terminal_at, request_id, request_region, actor_arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: HandshakeTags :many
SELECT * FROM org_handshake_tags WHERE partition = ? AND handshake_id = ? ORDER BY key;

-- name: PutHandshakeTag :exec
INSERT INTO org_handshake_tags (partition, handshake_id, key, value) VALUES (?, ?, ?, ?);

-- name: HandshakeApprovals :many
SELECT account_id, approved FROM org_handshake_approvals WHERE partition = ? AND handshake_id = ? ORDER BY account_id;

-- name: PutHandshakeApproval :exec
INSERT INTO org_handshake_approvals (partition, handshake_id, account_id, approved) VALUES (?, ?, ?, ?);

-- name: EffectivePolicies :many
SELECT * FROM org_effective_policies WHERE partition = ? AND org_id = ? ORDER BY account_id, policy_type;

-- name: PutEffectivePolicy :exec
INSERT INTO org_effective_policies (partition, org_id, account_id, policy_type, content, updated_at, due, request_id, request_region, actor_arn, validation_path)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: EffectivePolicyErrors :many
SELECT * FROM org_effective_policy_errors WHERE partition=? AND org_id=? AND account_id=? AND policy_type=? ORDER BY position;

-- name: EffectivePolicyErrorSources :many
SELECT policy_id FROM org_effective_policy_error_sources WHERE partition=? AND org_id=? AND account_id=? AND policy_type=? AND error_position=? ORDER BY position;

-- name: PutEffectivePolicyError :exec
INSERT INTO org_effective_policy_errors (partition,org_id,account_id,policy_type,position,code,message,path) VALUES (?,?,?,?,?,?,?,?);

-- name: PutEffectivePolicyErrorSource :exec
INSERT INTO org_effective_policy_error_sources (partition,org_id,account_id,policy_type,error_position,position,policy_id) VALUES (?,?,?,?,?,?,?);
