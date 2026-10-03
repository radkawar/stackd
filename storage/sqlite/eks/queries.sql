-- name: GetCluster :one
SELECT * FROM eks_cluster WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListClusters :many
SELECT * FROM eks_cluster WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;

-- name: AllClusters :many
SELECT * FROM eks_cluster ORDER BY partition, account_id, region, name;

-- name: PutCluster :exec
INSERT INTO eks_cluster (partition, account_id, region, name, id, role_arn, kubernetes_version, status, operation, error, endpoint, certificate_authority, vpc_id, subnets, security_groups, tags, created, due, generation, client_token, request_hash, creator_arn, creator_id, authentication_mode, bootstrap_admin, deletion_protection, enabled_log_types)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET
 id = excluded.id,
 role_arn = excluded.role_arn,
 kubernetes_version = excluded.kubernetes_version,
 status = excluded.status,
 operation = excluded.operation,
 error = excluded.error,
 endpoint = excluded.endpoint,
 certificate_authority = excluded.certificate_authority,
 vpc_id = excluded.vpc_id,
 subnets = excluded.subnets,
 security_groups = excluded.security_groups,
 tags = excluded.tags,
 created = excluded.created,
 due = excluded.due,
 generation = excluded.generation,
 client_token = excluded.client_token,
 request_hash = excluded.request_hash,
 creator_arn = excluded.creator_arn,
 creator_id = excluded.creator_id,
 authentication_mode = excluded.authentication_mode,
 bootstrap_admin = excluded.bootstrap_admin,
 deletion_protection = excluded.deletion_protection,
 enabled_log_types = excluded.enabled_log_types;

-- name: DeleteCluster :exec
DELETE FROM eks_cluster WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetAccessEntry :one
SELECT * FROM eks_access_entry WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ?;

-- name: ListAccessEntries :many
SELECT * FROM eks_access_entry WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY principal_arn;

-- name: PutAccessEntry :exec
INSERT INTO eks_access_entry (partition, account_id, region, name, principal_arn, principal_id, username, type, groups, tags, created, modified, id, client_token, request_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, principal_arn) DO UPDATE SET
 id = excluded.id,
 client_token = excluded.client_token,
 request_hash = excluded.request_hash,
 principal_id = excluded.principal_id,
 username = excluded.username,
 type = excluded.type,
 groups = excluded.groups,
 tags = excluded.tags,
 created = excluded.created,
 modified = excluded.modified;

-- name: DeleteAccessEntry :exec
DELETE FROM eks_access_entry WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ?;

-- name: DeleteClusterAccessEntries :exec
DELETE FROM eks_access_entry WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: ListAccessPolicies :many
SELECT * FROM eks_access_policy WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ? ORDER BY principal_arn, policy_arn;

-- name: PutAccessPolicy :exec
INSERT INTO eks_access_policy (partition, account_id, region, name, principal_arn, policy_arn, scope_type, namespaces, associated, modified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, principal_arn, policy_arn) DO UPDATE SET
 scope_type = excluded.scope_type,
 namespaces = excluded.namespaces,
 associated = excluded.associated,
 modified = excluded.modified;

-- name: DeleteAccessPolicy :exec
DELETE FROM eks_access_policy WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ? AND policy_arn = ?;

-- name: DeleteClusterAccessPolicies :exec
DELETE FROM eks_access_policy WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetUpdate :one
SELECT * FROM eks_update WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND id = ?;

-- name: ListUpdates :many
SELECT * FROM eks_update WHERE partition = ? AND account_id = ? AND region = ? AND name = ? ORDER BY id;

-- name: PutUpdate :exec
INSERT INTO eks_update (partition, account_id, region, name, id, type, status, error_code, error_message, client_token, request_hash, created, deletion_protection, authentication_mode, kubernetes_version, enabled_log_types, resource_type, resource_name, params_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, id) DO UPDATE SET
 type = excluded.type,
 status = excluded.status,
 error_code = excluded.error_code,
 error_message = excluded.error_message,
 client_token = excluded.client_token,
 request_hash = excluded.request_hash,
 created = excluded.created,
 deletion_protection = excluded.deletion_protection,
 authentication_mode = excluded.authentication_mode,
 kubernetes_version = excluded.kubernetes_version,
 enabled_log_types = excluded.enabled_log_types,
 resource_type = excluded.resource_type,
 resource_name = excluded.resource_name,
 params_json = excluded.params_json;

-- name: DeleteClusterUpdates :exec
DELETE FROM eks_update WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: DeletePrincipalPolicies :exec
DELETE FROM eks_access_policy WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ?;

-- name: GetAccessMutation :one
SELECT * FROM eks_access_mutation WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ? AND token = ?;

-- name: PutAccessMutation :exec
INSERT INTO eks_access_mutation (partition, account_id, region, name, principal_arn, token, request_hash)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name, principal_arn, token) DO UPDATE SET
 request_hash = excluded.request_hash;

-- name: DeletePrincipalMutations :exec
DELETE FROM eks_access_mutation WHERE partition = ? AND account_id = ? AND region = ? AND name = ? AND principal_arn = ?;

-- name: DeleteClusterAccessMutations :exec
DELETE FROM eks_access_mutation WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
