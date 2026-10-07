-- name: GetGlueRegistry :one
SELECT * FROM glue_registries WHERE partition=? AND account_id=? AND region=? AND registry_name=?;
-- name: ListGlueRegistries :many
SELECT * FROM glue_registries WHERE partition=? AND account_id=? AND region=? ORDER BY registry_name;
-- name: PutGlueRegistry :exec
INSERT INTO glue_registries (cfn_owner,partition,account_id,region,registry_name,description,status,created_at,updated_at,due_at)
VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (partition,account_id,region,registry_name) DO UPDATE SET
 description=excluded.description,status=excluded.status,created_at=excluded.created_at,updated_at=excluded.updated_at,due_at=excluded.due_at;
-- name: DeleteGlueRegistry :exec
DELETE FROM glue_registries WHERE partition=? AND account_id=? AND region=? AND registry_name=?;
-- name: ListGlueRegistryTags :many
SELECT tag_key,tag_value FROM glue_registry_tags WHERE partition=? AND account_id=? AND region=? AND registry_name=? ORDER BY tag_key;
-- name: DeleteGlueRegistryTags :exec
DELETE FROM glue_registry_tags WHERE partition=? AND account_id=? AND region=? AND registry_name=?;
-- name: PutGlueRegistryTag :exec
INSERT INTO glue_registry_tags (partition,account_id,region,registry_name,tag_key,tag_value) VALUES (?,?,?,?,?,?);
-- name: NextGlueRegistryDeletion :one
SELECT * FROM glue_registries WHERE status='DELETING' ORDER BY due_at,partition,account_id,region,registry_name LIMIT 1;
