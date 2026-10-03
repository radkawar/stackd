-- name: GetKeySet :one
SELECT * FROM kms_key_sets WHERE partition = ? AND account = ? AND key_id = ?;

-- name: ListScopes :many
SELECT DISTINCT partition, account, region FROM kms_keys ORDER BY partition, account, region;

-- name: MultiRegionPrimaryRegions :many
SELECT DISTINCT primary_region FROM kms_key_sets WHERE partition = ? AND account = ? AND multi_region = 1 ORDER BY primary_region;

-- name: PutKeySet :exec
INSERT INTO kms_key_sets (partition, account, key_id, spec, usage, origin, current_material_id, pending_material_id, rotation_enabled, rotation_period_days, rotation_next, rotation_started, multi_region, primary_region)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, key_id) DO UPDATE SET
    spec = excluded.spec,
    usage = excluded.usage,
    origin = excluded.origin,
    current_material_id = excluded.current_material_id,
    pending_material_id = excluded.pending_material_id,
    rotation_enabled = excluded.rotation_enabled,
    rotation_period_days = excluded.rotation_period_days,
    rotation_next = excluded.rotation_next,
    rotation_started = excluded.rotation_started,
    multi_region = excluded.multi_region,
    primary_region = excluded.primary_region;

-- name: DeleteKeySet :exec
DELETE FROM kms_key_sets WHERE partition = ? AND account = ? AND key_id = ?;

-- name: ListMaterials :many
SELECT * FROM kms_materials WHERE partition = ? AND account = ? AND key_id = ? ORDER BY position;

-- name: ClearMaterials :exec
DELETE FROM kms_materials WHERE partition = ? AND account = ? AND key_id = ?;

-- name: InsertMaterial :exec
INSERT INTO kms_materials (partition, account, key_id, position, material_id, material, rotation_date, rotation_type, description)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListReplicaRegions :many
SELECT * FROM kms_replica_regions WHERE partition = ? AND account = ? AND key_id = ? ORDER BY position;

-- name: ClearReplicaRegions :exec
DELETE FROM kms_replica_regions WHERE partition = ? AND account = ? AND key_id = ?;

-- name: InsertReplicaRegion :exec
INSERT INTO kms_replica_regions (partition, account, key_id, position, region)
VALUES (?, ?, ?, ?, ?);

-- name: ListPrincipals :many
SELECT * FROM kms_principals WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY reference;

-- name: ClearPrincipals :exec
DELETE FROM kms_principals WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: InsertPrincipal :exec
INSERT INTO kms_principals (partition, account, region, key_id, reference, principal_id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListTags :many
SELECT * FROM kms_tags WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY tag_key;

-- name: ClearTags :exec
DELETE FROM kms_tags WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: InsertTag :exec
INSERT INTO kms_tags (partition, account, region, key_id, tag_key, tag_value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListImports :many
SELECT * FROM kms_imports WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY material_id;

-- name: ClearImports :exec
DELETE FROM kms_imports WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: InsertImport :exec
INSERT INTO kms_imports (partition, account, region, key_id, material_id, valid_to)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListImportParameters :many
SELECT * FROM kms_import_parameters WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY position;

-- name: ClearImportParameters :exec
DELETE FROM kms_import_parameters WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: InsertImportParameter :exec
INSERT INTO kms_import_parameters (partition, account, region, key_id, position, token, private_key, algorithm, valid_to)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListGrants :many
SELECT * FROM kms_grants WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY grant_id;

-- name: ClearGrants :exec
DELETE FROM kms_grants WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: InsertGrant :exec
INSERT INTO kms_grants (partition, account, region, key_id, grant_id, name, grantee, grantee_id, retiring, retiring_id, issuer, created)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListGrantLists :many
SELECT * FROM kms_grant_lists WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY grant_id, kind, position;

-- name: InsertGrantList :exec
INSERT INTO kms_grant_lists (partition, account, region, key_id, grant_id, kind, position, value)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListGrantConstraints :many
SELECT * FROM kms_grant_constraints WHERE partition = ? AND account = ? AND region = ? AND key_id = ? ORDER BY grant_id, kind, tag_key;

-- name: InsertGrantConstraint :exec
INSERT INTO kms_grant_constraints (partition, account, region, key_id, grant_id, kind, tag_key, tag_value)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListKeys :many
SELECT * FROM kms_keys WHERE partition = ? AND account = ? AND region = ? ORDER BY key_id;

-- name: PutKey :exec
INSERT INTO kms_keys (partition, account, region, key_id, arn, description, manager, state, created, deletion, available_at, pending_deletion_days, policy)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region, key_id) DO UPDATE SET
    arn = excluded.arn,
    description = excluded.description,
    manager = excluded.manager,
    state = excluded.state,
    created = excluded.created,
    deletion = excluded.deletion,
    available_at = excluded.available_at,
    pending_deletion_days = excluded.pending_deletion_days,
    policy = excluded.policy;

-- name: DeleteKey :exec
DELETE FROM kms_keys WHERE partition = ? AND account = ? AND region = ? AND key_id = ?;

-- name: ListAliases :many
SELECT * FROM kms_aliases WHERE partition = ? AND account = ? AND region = ? ORDER BY name;

-- name: PutAlias :exec
INSERT INTO kms_aliases (partition, account, region, name, key_id, created, updated, owner_stack_id, owner_logical_id, owner_token)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region, name) DO UPDATE SET
    key_id = excluded.key_id,
    created = excluded.created,
    updated = excluded.updated,
    owner_stack_id = excluded.owner_stack_id,
    owner_logical_id = excluded.owner_logical_id,
    owner_token = excluded.owner_token;

-- name: DeleteAlias :exec
DELETE FROM kms_aliases WHERE partition = ? AND account = ? AND region = ? AND name = ?;
