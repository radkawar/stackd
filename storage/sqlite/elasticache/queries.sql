-- name: GetCluster :one
SELECT * FROM elasticache_cluster WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListClusters :many
SELECT * FROM elasticache_cluster WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: AllClusters :many
SELECT * FROM elasticache_cluster ORDER BY partition, account_id, region, kind, name;
-- name: PutCluster :exec
INSERT INTO elasticache_cluster (partition, account_id, region, kind, name, engine, engine_version, node_type, description, parameter_group, user_group, runtime_id, status, operation, restore_snapshot, shards, replicas, cluster_mode, tls_enabled, memory_bytes, version, created, due, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET engine = excluded.engine, engine_version = excluded.engine_version, node_type = excluded.node_type, description = excluded.description, parameter_group = excluded.parameter_group, user_group = excluded.user_group, runtime_id = excluded.runtime_id, status = excluded.status, operation = excluded.operation, restore_snapshot = excluded.restore_snapshot, shards = excluded.shards, replicas = excluded.replicas, cluster_mode = excluded.cluster_mode, tls_enabled = excluded.tls_enabled, memory_bytes = excluded.memory_bytes, version = excluded.version, created = excluded.created, due = excluded.due, cloudformation_owner = excluded.cloudformation_owner;
-- name: DeleteCluster :exec
DELETE FROM elasticache_cluster WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: GetSnapshot :one
SELECT * FROM elasticache_snapshot WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListSnapshots :many
SELECT * FROM elasticache_snapshot WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: AllSnapshots :many
SELECT * FROM elasticache_snapshot ORDER BY partition, account_id, region, kind, name;
-- name: PutSnapshot :exec
INSERT INTO elasticache_snapshot (partition, account_id, region, kind, name, source_kind, source, source_runtime_id, runtime_id, copy_source, engine, engine_version, node_type, status, operation, shards, replicas, cluster_mode, tls_enabled, memory_bytes, version, created, due) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET source_kind = excluded.source_kind, source = excluded.source, source_runtime_id = excluded.source_runtime_id, runtime_id = excluded.runtime_id, copy_source = excluded.copy_source, engine = excluded.engine, engine_version = excluded.engine_version, node_type = excluded.node_type, status = excluded.status, operation = excluded.operation, shards = excluded.shards, replicas = excluded.replicas, cluster_mode = excluded.cluster_mode, tls_enabled = excluded.tls_enabled, memory_bytes = excluded.memory_bytes, version = excluded.version, created = excluded.created, due = excluded.due;
-- name: DeleteSnapshot :exec
DELETE FROM elasticache_snapshot WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: GetUser :one
SELECT * FROM elasticache_user WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListUsers :many
SELECT * FROM elasticache_user WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: PutUser :exec
INSERT INTO elasticache_user (partition, account_id, region, kind, name, user_name, engine, access_string, status, no_password, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET user_name = excluded.user_name, engine = excluded.engine, access_string = excluded.access_string, status = excluded.status, no_password = excluded.no_password, cloudformation_owner = excluded.cloudformation_owner;
-- name: DeleteUser :exec
DELETE FROM elasticache_user WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: GetUserGroup :one
SELECT * FROM elasticache_user_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListUserGroups :many
SELECT * FROM elasticache_user_group WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: PutUserGroup :exec
INSERT INTO elasticache_user_group (partition, account_id, region, kind, name, engine, status, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET engine = excluded.engine, status = excluded.status, cloudformation_owner = excluded.cloudformation_owner;
-- name: DeleteUserGroup :exec
DELETE FROM elasticache_user_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: GetParameterGroup :one
SELECT * FROM elasticache_parameter_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListParameterGroups :many
SELECT * FROM elasticache_parameter_group WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: PutParameterGroup :exec
INSERT INTO elasticache_parameter_group (partition, account_id, region, kind, name, family, description, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET family = excluded.family, description = excluded.description, cloudformation_owner = excluded.cloudformation_owner;
-- name: DeleteParameterGroup :exec
DELETE FROM elasticache_parameter_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: GetSubnetGroup :one
SELECT * FROM elasticache_subnet_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListSubnetGroups :many
SELECT * FROM elasticache_subnet_group WHERE partition = ? AND account_id = ? AND region = ? ORDER BY kind, name;
-- name: PutSubnetGroup :exec
INSERT INTO elasticache_subnet_group (partition, account_id, region, kind, name, description, vpc_id, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition, account_id, region, kind, name) DO UPDATE SET description = excluded.description, vpc_id = excluded.vpc_id, cloudformation_owner = excluded.cloudformation_owner;
-- name: DeleteSubnetGroup :exec
DELETE FROM elasticache_subnet_group WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListTags :many
SELECT * FROM elasticache_tag WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY tag_key;
-- name: PutTag :exec
INSERT INTO elasticache_tag (partition, account_id, region, kind, name, tag_key, tag_value) VALUES (?, ?, ?, ?, ?, ?, ?);
-- name: DeleteTags :exec
DELETE FROM elasticache_tag WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListParameters :many
SELECT * FROM elasticache_parameter WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY parameter_name;
-- name: PutParameter :exec
INSERT INTO elasticache_parameter (partition, account_id, region, kind, name, parameter_name, parameter_value) VALUES (?, ?, ?, ?, ?, ?, ?);
-- name: DeleteParameters :exec
DELETE FROM elasticache_parameter WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListNodes :many
SELECT * FROM elasticache_node WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY ordinal;
-- name: PutNode :exec
INSERT INTO elasticache_node (partition, account_id, region, kind, name, node_id, address, ordinal, shard, replica, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
-- name: DeleteNodes :exec
DELETE FROM elasticache_node WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListHashs :many
SELECT * FROM elasticache_password_hash WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY ordinal;
-- name: PutHash :exec
INSERT INTO elasticache_password_hash (partition, account_id, region, kind, name, hex_hash, ordinal) VALUES (?, ?, ?, ?, ?, ?, ?);
-- name: DeleteHashs :exec
DELETE FROM elasticache_password_hash WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListMembers :many
SELECT * FROM elasticache_member WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY user_id;
-- name: PutMember :exec
INSERT INTO elasticache_member (partition, account_id, region, kind, name, user_id) VALUES (?, ?, ?, ?, ?, ?);
-- name: DeleteMembers :exec
DELETE FROM elasticache_member WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
-- name: ListSubnets :many
SELECT * FROM elasticache_subnet WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ? ORDER BY subnet_id;
-- name: PutSubnet :exec
INSERT INTO elasticache_subnet (partition, account_id, region, kind, name, subnet_id, vpc_id, availability_zone) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
-- name: DeleteSubnets :exec
DELETE FROM elasticache_subnet WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?;
