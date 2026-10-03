-- name: GetLayerVersion :one
SELECT * FROM lambda_layer_versions WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=?;
-- name: GetOwnedLayerVersion :one
SELECT * FROM lambda_layer_versions WHERE partition=? AND account=? AND region=? AND layer_name=? AND owner_stack_id=? AND owner_logical_id=? AND owner_token=?
AND owner_stack_id<>'' AND owner_logical_id<>'' AND owner_token<>'';
-- name: ListLayerVersions :many
SELECT * FROM lambda_layer_versions WHERE partition=? AND account=? AND region=? AND layer_name=? ORDER BY version DESC;
-- name: ListLayers :many
SELECT v.* FROM lambda_layer_versions AS v
WHERE v.partition=? AND v.account=? AND v.region=?
AND NOT EXISTS (SELECT 1 FROM lambda_layer_versions AS newer WHERE newer.partition=v.partition AND newer.account=v.account AND newer.region=v.region AND newer.layer_name=v.layer_name AND newer.version>v.version)
ORDER BY v.layer_name;
-- name: AllocateLayerVersion :one
INSERT INTO lambda_layer_version_allocations(partition,account,region,layer_name,last_version) VALUES(?,?,?,?,1)
ON CONFLICT(partition,account,region,layer_name) DO UPDATE SET last_version=last_version+1 WHERE last_version<9223372036854775807 RETURNING last_version;
-- name: PutLayerVersion :execrows
INSERT INTO lambda_layer_versions(partition,account,region,layer_name,version,code_sha256,code_size,description,license_info,created,has_compatible_runtimes,has_compatible_architectures,has_reference,reference_bucket,reference_key,reference_version_id,signing_profile_version_arn,signing_job_arn,owner_stack_id,owner_logical_id,owner_token)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,layer_name,version) DO NOTHING;
-- name: DeleteLayerVersion :exec
DELETE FROM lambda_layer_versions WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=?;
-- name: GetLayerCompatibleRuntimes :many
SELECT runtime FROM lambda_layer_compatible_runtimes WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=? ORDER BY position;
-- name: PutLayerCompatibleRuntime :exec
INSERT INTO lambda_layer_compatible_runtimes(partition,account,region,layer_name,version,position,runtime) VALUES(?,?,?,?,?,?,?);
-- name: GetLayerCompatibleArchitectures :many
SELECT architecture FROM lambda_layer_compatible_architectures WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=? ORDER BY position;
-- name: PutLayerCompatibleArchitecture :exec
INSERT INTO lambda_layer_compatible_architectures(partition,account,region,layer_name,version,position,architecture) VALUES(?,?,?,?,?,?,?);
-- name: GetLayerPolicy :one
SELECT document,revision FROM lambda_layer_policies WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=?;
-- name: PutLayerPolicy :exec
INSERT INTO lambda_layer_policies(partition,account,region,layer_name,version,document,revision) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,layer_name,version) DO UPDATE SET document=excluded.document,revision=excluded.revision;
-- name: DeleteLayerPolicy :exec
DELETE FROM lambda_layer_policies WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=?;
-- name: GetLayerPolicyPrincipals :many
SELECT principal,principal_id FROM lambda_layer_policy_principals WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=? ORDER BY principal;
-- name: DeleteLayerPolicyPrincipals :exec
DELETE FROM lambda_layer_policy_principals WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=?;
-- name: PutLayerPolicyPrincipal :exec
INSERT INTO lambda_layer_policy_principals(partition,account,region,layer_name,version,principal,principal_id) VALUES(?,?,?,?,?,?,?);
-- name: GetLayerPermissionOwner :one
SELECT owner_stack_id,owner_logical_id,owner_token FROM lambda_layer_permission_owners WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=? AND statement_id=?;
-- name: PutLayerPermissionOwner :exec
INSERT INTO lambda_layer_permission_owners(partition,account,region,layer_name,version,statement_id,owner_stack_id,owner_logical_id,owner_token) VALUES(?,?,?,?,?,?,?,?,?);
-- name: DeleteLayerPermissionOwner :exec
DELETE FROM lambda_layer_permission_owners WHERE partition=? AND account=? AND region=? AND layer_name=? AND version=? AND statement_id=?;
-- name: GetFunctionLayers :many
SELECT * FROM lambda_function_layers WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=? ORDER BY position;
-- name: DeleteFunctionLayers :exec
DELETE FROM lambda_function_layers WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionLayer :exec
INSERT INTO lambda_function_layers(partition,account,region,function_name,pending,version,position,layer_partition,layer_account,layer_region,layer_name,layer_version,code_sha256,code_size,signing_profile_version_arn,signing_job_arn) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
