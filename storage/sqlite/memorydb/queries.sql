-- name: GetCluster :one
SELECT * FROM memorydb_clusters WHERE arn = ?;
-- name: ListCluster :many
SELECT * FROM memorydb_clusters WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutCluster :exec
INSERT INTO memorydb_clusters (arn, partition, account_id, region, name, runtime_id, status, operation, description, node_type, engine, engine_version, acl_name, parameter_group, restore_snapshot, shards, replicas, tls_enabled, version, created, due, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, runtime_id=excluded.runtime_id, status=excluded.status, operation=excluded.operation, description=excluded.description, node_type=excluded.node_type, engine=excluded.engine, engine_version=excluded.engine_version, acl_name=excluded.acl_name, parameter_group=excluded.parameter_group, restore_snapshot=excluded.restore_snapshot, shards=excluded.shards, replicas=excluded.replicas, tls_enabled=excluded.tls_enabled, version=excluded.version, created=excluded.created, due=excluded.due, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteCluster :exec
DELETE FROM memorydb_clusters WHERE arn = ?;
-- name: AllCluster :many
SELECT * FROM memorydb_clusters ORDER BY arn;
-- name: GetUser :one
SELECT * FROM memorydb_users WHERE arn = ?;
-- name: ListUser :many
SELECT * FROM memorydb_users WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutUser :exec
INSERT INTO memorydb_users (arn, partition, account_id, region, name, access_string, authentication, status, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, access_string=excluded.access_string, authentication=excluded.authentication, status=excluded.status, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteUser :exec
DELETE FROM memorydb_users WHERE arn = ?;
-- name: GetACL :one
SELECT * FROM memorydb_acls WHERE arn = ?;
-- name: ListACL :many
SELECT * FROM memorydb_acls WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutACL :exec
INSERT INTO memorydb_acls (arn, partition, account_id, region, name, status, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, status=excluded.status, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteACL :exec
DELETE FROM memorydb_acls WHERE arn = ?;
-- name: GetParameterGroup :one
SELECT * FROM memorydb_parameter_groups WHERE arn = ?;
-- name: ListParameterGroup :many
SELECT * FROM memorydb_parameter_groups WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutParameterGroup :exec
INSERT INTO memorydb_parameter_groups (arn, partition, account_id, region, name, family, description, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, family=excluded.family, description=excluded.description, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteParameterGroup :exec
DELETE FROM memorydb_parameter_groups WHERE arn = ?;
-- name: GetSubnetGroup :one
SELECT * FROM memorydb_subnet_groups WHERE arn = ?;
-- name: ListSubnetGroup :many
SELECT * FROM memorydb_subnet_groups WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutSubnetGroup :exec
INSERT INTO memorydb_subnet_groups (arn, partition, account_id, region, name, description, vpc_id, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, description=excluded.description, vpc_id=excluded.vpc_id, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteSubnetGroup :exec
DELETE FROM memorydb_subnet_groups WHERE arn = ?;
-- name: GetSnapshot :one
SELECT * FROM memorydb_snapshots WHERE arn = ?;
-- name: ListSnapshot :many
SELECT * FROM memorydb_snapshots WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: PutSnapshot :exec
INSERT INTO memorydb_snapshots (arn, partition, account_id, region, name, runtime_id, source_runtime_id, source, copy_source, status, operation, engine, engine_version, node_type, parameter_group, acl_name, shards, replicas, tls_enabled, version, created, due, cloudformation_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition, account_id=excluded.account_id, region=excluded.region, name=excluded.name, runtime_id=excluded.runtime_id, source_runtime_id=excluded.source_runtime_id, source=excluded.source, copy_source=excluded.copy_source, status=excluded.status, operation=excluded.operation, engine=excluded.engine, engine_version=excluded.engine_version, node_type=excluded.node_type, parameter_group=excluded.parameter_group, acl_name=excluded.acl_name, shards=excluded.shards, replicas=excluded.replicas, tls_enabled=excluded.tls_enabled, version=excluded.version, created=excluded.created, due=excluded.due, cloudformation_owner=excluded.cloudformation_owner;
-- name: DeleteSnapshot :exec
DELETE FROM memorydb_snapshots WHERE arn = ?;
-- name: AllSnapshot :many
SELECT * FROM memorydb_snapshots ORDER BY arn;
-- name: ListTag :many
SELECT * FROM memorydb_tags WHERE owner_arn = ? ORDER BY tag_key;
-- name: ClearTag :exec
DELETE FROM memorydb_tags WHERE owner_arn = ?;
-- name: PutTag :exec
INSERT INTO memorydb_tags (owner_arn,tag_key,tag_value) VALUES (?,?,?);
-- name: ListNode :many
SELECT * FROM memorydb_nodes WHERE owner_arn = ? ORDER BY node_id;
-- name: ClearNode :exec
DELETE FROM memorydb_nodes WHERE owner_arn = ?;
-- name: PutNode :exec
INSERT INTO memorydb_nodes (owner_arn,node_id,shard,replica,address,port) VALUES (?,?,?,?,?,?);
-- name: ListPasswordHash :many
SELECT * FROM memorydb_password_hashes WHERE owner_arn = ? ORDER BY password_hash;
-- name: ClearPasswordHash :exec
DELETE FROM memorydb_password_hashes WHERE owner_arn = ?;
-- name: PutPasswordHash :exec
INSERT INTO memorydb_password_hashes (owner_arn,password_hash) VALUES (?,?);
-- name: ListACLUser :many
SELECT * FROM memorydb_acl_users WHERE owner_arn = ? ORDER BY user_name;
-- name: ClearACLUser :exec
DELETE FROM memorydb_acl_users WHERE owner_arn = ?;
-- name: PutACLUser :exec
INSERT INTO memorydb_acl_users (owner_arn,user_name) VALUES (?,?);
-- name: ListParameter :many
SELECT * FROM memorydb_parameters WHERE owner_arn = ? ORDER BY parameter_name;
-- name: ClearParameter :exec
DELETE FROM memorydb_parameters WHERE owner_arn = ?;
-- name: PutParameter :exec
INSERT INTO memorydb_parameters (owner_arn,parameter_name,parameter_value) VALUES (?,?,?);
-- name: ListSubnet :many
SELECT * FROM memorydb_subnets WHERE owner_arn = ? ORDER BY subnet_id;
-- name: ClearSubnet :exec
DELETE FROM memorydb_subnets WHERE owner_arn = ?;
-- name: PutSubnet :exec
INSERT INTO memorydb_subnets (owner_arn,subnet_id,vpc_id,availability_zone) VALUES (?,?,?,?);
