-- name: GetGlobalCluster :one
SELECT * FROM rds_global_cluster WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND name=sqlc.arg(name);

-- name: ListGlobalClusters :many
SELECT * FROM rds_global_cluster WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) ORDER BY name;

-- name: PutGlobalCluster :exec
INSERT INTO rds_global_cluster (partition,account_id,name,resource_id,engine,engine_version,database_name,engine_lifecycle_support,deletion_protection,storage_encrypted) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(name),sqlc.arg(resource_id),sqlc.arg(engine),sqlc.arg(engine_version),sqlc.arg(database_name),sqlc.arg(engine_lifecycle_support),sqlc.arg(deletion_protection),sqlc.arg(storage_encrypted)) ON CONFLICT (partition,account_id,name) DO UPDATE SET resource_id=excluded.resource_id,engine=excluded.engine,engine_version=excluded.engine_version,database_name=excluded.database_name,engine_lifecycle_support=excluded.engine_lifecycle_support,deletion_protection=excluded.deletion_protection,storage_encrypted=excluded.storage_encrypted;

-- name: DeleteGlobalCluster :exec
DELETE FROM rds_global_cluster WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND name=sqlc.arg(name);
