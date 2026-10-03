-- name: GetCluster :one
SELECT * FROM docdb_cluster WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListClusters :many
SELECT * FROM docdb_cluster ORDER BY partition,account_id,region,name;

-- name: PutCluster :exec
INSERT INTO docdb_cluster (partition, account_id, region, name, runtime_id, username, engine_version, status, operation, restore_snapshot, ciphertext, pending_ciphertext, address, port, replica_set, ca, requested_port, version, created, due, deletion_protection) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET runtime_id=excluded.runtime_id, username=excluded.username, engine_version=excluded.engine_version, status=excluded.status, operation=excluded.operation, restore_snapshot=excluded.restore_snapshot, ciphertext=excluded.ciphertext, pending_ciphertext=excluded.pending_ciphertext, address=excluded.address, port=excluded.port, replica_set=excluded.replica_set, ca=excluded.ca, requested_port=excluded.requested_port, version=excluded.version, created=excluded.created, due=excluded.due, deletion_protection=excluded.deletion_protection;

-- name: DeleteCluster :exec
DELETE FROM docdb_cluster WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetInstance :one
SELECT * FROM docdb_instance WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListInstances :many
SELECT * FROM docdb_instance ORDER BY partition,account_id,region,name;

-- name: PutInstance :exec
INSERT INTO docdb_instance (partition, account_id, region, name, cluster, class, runtime_id, status, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET cluster=excluded.cluster, class=excluded.class, runtime_id=excluded.runtime_id, status=excluded.status, created=excluded.created;

-- name: DeleteInstance :exec
DELETE FROM docdb_instance WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetSnapshot :one
SELECT * FROM docdb_snapshot WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListSnapshots :many
SELECT * FROM docdb_snapshot ORDER BY partition,account_id,region,name;

-- name: PutSnapshot :exec
INSERT INTO docdb_snapshot (partition, account_id, region, name, source, source_runtime_id, runtime_id, username, engine_version, status, operation, ciphertext, version, created, due) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET source=excluded.source, source_runtime_id=excluded.source_runtime_id, runtime_id=excluded.runtime_id, username=excluded.username, engine_version=excluded.engine_version, status=excluded.status, operation=excluded.operation, ciphertext=excluded.ciphertext, version=excluded.version, created=excluded.created, due=excluded.due;

-- name: DeleteSnapshot :exec
DELETE FROM docdb_snapshot WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListTags :many
SELECT tag_key,tag_value FROM docdb_tag WHERE partition=? AND account_id=? AND region=? AND kind=? AND name=? ORDER BY tag_key;

-- name: DeleteTags :exec
DELETE FROM docdb_tag WHERE partition=? AND account_id=? AND region=? AND kind=? AND name=?;

-- name: PutTag :exec
INSERT INTO docdb_tag(partition,account_id,region,kind,name,tag_key,tag_value) VALUES (?,?,?,?,?,?,?);
