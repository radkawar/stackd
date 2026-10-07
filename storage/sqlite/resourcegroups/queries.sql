-- name: GetGroup :one
SELECT * FROM resourcegroups_groups
WHERE partition = ? AND account_id = ? AND region = ?
  AND (arn = sqlc.arg(identifier) OR name = sqlc.arg(identifier));

-- name: ListGroups :many
SELECT * FROM resourcegroups_groups
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY arn;

-- name: PutGroup :execrows
INSERT INTO resourcegroups_groups (arn, partition, account_id, region, name, description, query_present, query_type, query_string, created, managed_type, application_arn, source_arn, source_name, parent_arn, incarnation, display_name, owner, criticality, cloudformation_claim)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn) DO UPDATE SET
    name = excluded.name, description = excluded.description,
    query_present = excluded.query_present,
    query_type = excluded.query_type, query_string = excluded.query_string,
    created = excluded.created, managed_type = excluded.managed_type,
    application_arn = excluded.application_arn, source_arn = excluded.source_arn,
    source_name = excluded.source_name, parent_arn = excluded.parent_arn,
    display_name = excluded.display_name, owner = excluded.owner, criticality = excluded.criticality
WHERE resourcegroups_groups.partition = excluded.partition
  AND resourcegroups_groups.account_id = excluded.account_id
  AND resourcegroups_groups.region = excluded.region;

-- name: DeleteGroup :exec
DELETE FROM resourcegroups_groups
WHERE partition = ? AND account_id = ? AND region = ?
  AND (arn = sqlc.arg(identifier) OR name = sqlc.arg(identifier));

-- name: ListGroupTags :many
SELECT * FROM resourcegroups_group_tags WHERE group_arn = ? ORDER BY tag_key;

-- name: PutGroupTag :exec
INSERT INTO resourcegroups_group_tags (group_arn, tag_key, tag_value) VALUES (?, ?, ?);

-- name: DeleteGroupTags :exec
DELETE FROM resourcegroups_group_tags WHERE group_arn = ?;

-- name: ListGroupings :many
SELECT * FROM resourcegroups_groupings WHERE group_arn = ? ORDER BY resource_arn;

-- name: PutGrouping :exec
INSERT INTO resourcegroups_groupings (group_arn, resource_arn, resource_type, incarnation, action, updated, task_arn, status, error_code, error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(group_arn, resource_arn) DO UPDATE SET
 resource_type = excluded.resource_type, incarnation = excluded.incarnation,
 action = excluded.action, updated = excluded.updated, task_arn = excluded.task_arn, status = excluded.status,
 error_code = excluded.error_code, error_message = excluded.error_message;

-- name: ListTagSyncTasks :many
SELECT * FROM resourcegroups_tag_sync_tasks ORDER BY arn;

-- name: PutTagSyncTask :exec
INSERT INTO resourcegroups_tag_sync_tasks (arn, group_arn, partition, account_id, region, group_name, role_arn, query_type, query_string, tag_key, tag_value, uses_tag, status, error_message, created, next_check, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn) DO UPDATE SET
 status = excluded.status, error_message = excluded.error_message,
 next_check = excluded.next_check, version = excluded.version;

-- name: DeleteTagSyncTask :exec
DELETE FROM resourcegroups_tag_sync_tasks WHERE arn = ?;

-- name: ListAppliedMemberships :many
SELECT * FROM resourcegroups_applied_memberships WHERE task_arn = ? ORDER BY resource_arn;

-- name: PutAppliedMembership :exec
INSERT INTO resourcegroups_applied_memberships (task_arn, resource_arn, resource_type, incarnation, applied_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(task_arn, resource_arn) DO UPDATE SET
 resource_type = excluded.resource_type, incarnation = excluded.incarnation, applied_at = excluded.applied_at;

-- name: DeleteAppliedMembership :exec
DELETE FROM resourcegroups_applied_memberships WHERE task_arn = ? AND resource_arn = ?;

-- name: ListLifecycleAccounts :many
SELECT * FROM resourcegroups_lifecycle_accounts ORDER BY partition, account_id, region;

-- name: PutLifecycleAccount :exec
INSERT INTO resourcegroups_lifecycle_accounts (partition, account_id, region, desired, status, message, initialized, next_check, version)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region) DO UPDATE SET
 desired = excluded.desired, status = excluded.status, message = excluded.message,
 initialized = excluded.initialized, next_check = excluded.next_check, version = excluded.version;

-- name: ListLifecycleSnapshots :many
SELECT * FROM resourcegroups_lifecycle_snapshots
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY group_arn;

-- name: PutLifecycleSnapshot :exec
INSERT INTO resourcegroups_lifecycle_snapshots (group_arn, partition, account_id, region, name, description, incarnation, query_type, query_string, created, managed_type, application_arn, source_arn, source_name, parent_arn, sequence)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(group_arn) DO UPDATE SET
 name = excluded.name, description = excluded.description, incarnation = excluded.incarnation,
 query_type = excluded.query_type, query_string = excluded.query_string, created = excluded.created,
 managed_type = excluded.managed_type, application_arn = excluded.application_arn,
 source_arn = excluded.source_arn, source_name = excluded.source_name, parent_arn = excluded.parent_arn,
 sequence = excluded.sequence;

-- name: DeleteLifecycleSnapshot :exec
DELETE FROM resourcegroups_lifecycle_snapshots WHERE group_arn = ?;

-- name: ListLifecycleMembers :many
SELECT * FROM resourcegroups_lifecycle_members WHERE group_arn = ? ORDER BY resource_arn;

-- name: DeleteLifecycleMembers :exec
DELETE FROM resourcegroups_lifecycle_members WHERE group_arn = ?;

-- name: PutLifecycleMember :exec
INSERT INTO resourcegroups_lifecycle_members (group_arn, resource_arn, resource_type, incarnation) VALUES (?, ?, ?, ?);
