-- name: GetAddon :one
SELECT * FROM eks_addons WHERE partition=? AND account_id=? AND region=? AND name=? AND addon_name=?;
-- name: ListAddons :many
SELECT * FROM eks_addons WHERE partition=? AND account_id=? AND region=? AND name=? ORDER BY addon_name;
-- name: DeleteAddon :exec
DELETE FROM eks_addons WHERE partition=? AND account_id=? AND region=? AND name=? AND addon_name=?;
-- name: PutAddon :exec
INSERT INTO eks_addons(partition,account_id,region,name,addon_name,id,version,applied_version,configuration,applied_configuration,status,operation,error,error_code,resolve_conflicts,update_id,client_token,request_hash,tags,created,modified,due,generation,preserve)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name,addon_name) DO UPDATE SET
id=excluded.id,version=excluded.version,applied_version=excluded.applied_version,configuration=excluded.configuration,applied_configuration=excluded.applied_configuration,status=excluded.status,operation=excluded.operation,error=excluded.error,error_code=excluded.error_code,resolve_conflicts=excluded.resolve_conflicts,update_id=excluded.update_id,client_token=excluded.client_token,request_hash=excluded.request_hash,tags=excluded.tags,created=excluded.created,modified=excluded.modified,due=excluded.due,generation=excluded.generation,preserve=excluded.preserve;
