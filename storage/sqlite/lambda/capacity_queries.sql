-- name: GetCapacityProvider :one
SELECT * FROM lambda_capacity_providers WHERE partition=? AND account=? AND region=? AND name=?;
-- name: ListCapacityProviders :many
SELECT * FROM lambda_capacity_providers WHERE partition=? AND account=? AND region=? ORDER BY name;
-- name: ListAllCapacityProviders :many
SELECT * FROM lambda_capacity_providers ORDER BY partition,account,region,name;
-- name: PutCapacityProvider :exec
INSERT INTO lambda_capacity_providers(partition,account,region,name,generation,state,state_reason,operator_role_arn,kms_key_arn,architecture,scaling_mode,max_vcpus,target_cpu,log_group,system_log_level,propagate_explicit,modified,owner_stack_id,owner_logical_id,owner_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,name) DO UPDATE SET generation=excluded.generation,state=excluded.state,state_reason=excluded.state_reason,operator_role_arn=excluded.operator_role_arn,kms_key_arn=excluded.kms_key_arn,architecture=excluded.architecture,scaling_mode=excluded.scaling_mode,max_vcpus=excluded.max_vcpus,target_cpu=excluded.target_cpu,log_group=excluded.log_group,system_log_level=excluded.system_log_level,propagate_explicit=excluded.propagate_explicit,modified=excluded.modified,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;
-- name: DeleteCapacityProvider :exec
DELETE FROM lambda_capacity_providers WHERE partition=? AND account=? AND region=? AND name=?;
-- name: ListCapacityProviderMembers :many
SELECT kind,position,value FROM lambda_capacity_provider_members WHERE partition=? AND account=? AND region=? AND provider_name=? ORDER BY kind,position;
-- name: DeleteCapacityProviderMembers :exec
DELETE FROM lambda_capacity_provider_members WHERE partition=? AND account=? AND region=? AND provider_name=?;
-- name: PutCapacityProviderMember :exec
INSERT INTO lambda_capacity_provider_members(partition,account,region,provider_name,kind,position,value) VALUES(?,?,?,?,?,?,?);
-- name: ListCapacityProviderTags :many
SELECT propagated,key,value FROM lambda_capacity_provider_tags WHERE partition=? AND account=? AND region=? AND provider_name=? ORDER BY propagated,key;
-- name: DeleteCapacityProviderTags :exec
DELETE FROM lambda_capacity_provider_tags WHERE partition=? AND account=? AND region=? AND provider_name=?;
-- name: PutCapacityProviderTag :exec
INSERT INTO lambda_capacity_provider_tags(partition,account,region,provider_name,propagated,key,value) VALUES(?,?,?,?,?,?,?);
-- name: GetFunctionCapacityConfig :one
SELECT provider_arn,memory_gib_per_vcpu,max_concurrency FROM lambda_function_capacity WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: DeleteFunctionCapacityConfig :exec
DELETE FROM lambda_function_capacity WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionCapacityConfig :exec
INSERT INTO lambda_function_capacity(partition,account,region,function_name,pending,version,provider_arn,memory_gib_per_vcpu,max_concurrency) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET provider_arn=excluded.provider_arn,memory_gib_per_vcpu=excluded.memory_gib_per_vcpu,max_concurrency=excluded.max_concurrency;
-- name: GetCapacityScaling :one
SELECT * FROM lambda_capacity_scaling WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: ListCapacityScalings :many
SELECT * FROM lambda_capacity_scaling WHERE partition=? AND account=? AND region=? AND function_name=? ORDER BY qualifier;
-- name: PutCapacityScaling :exec
INSERT INTO lambda_capacity_scaling(partition,account,region,function_name,qualifier,generation,min_environments,max_environments,applied_min,applied_max,modified) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,qualifier) DO UPDATE SET generation=excluded.generation,min_environments=excluded.min_environments,max_environments=excluded.max_environments,applied_min=excluded.applied_min,applied_max=excluded.applied_max,modified=excluded.modified;
-- name: DeleteCapacityScaling :exec
DELETE FROM lambda_capacity_scaling WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: ListCapacityGuests :many
SELECT * FROM lambda_capacity_guests WHERE partition=? AND account=? AND region=? AND provider_name=? ORDER BY id;
-- name: PutCapacityGuest :exec
INSERT INTO lambda_capacity_guests(id,partition,account,region,provider_name,generation,instance_id,subnet_id,instance_type,endpoint,agent_token,agent_certificate,agent_private_key,command_id,state,error,vcpus,memory_mb,modified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,subnet_id=excluded.subnet_id,instance_type=excluded.instance_type,endpoint=excluded.endpoint,command_id=excluded.command_id,state=excluded.state,error=excluded.error,vcpus=excluded.vcpus,memory_mb=excluded.memory_mb,modified=excluded.modified;
-- name: DeleteCapacityGuest :exec
DELETE FROM lambda_capacity_guests WHERE partition=? AND account=? AND region=? AND provider_name=? AND id=?;
-- name: ListCapacityEnvironments :many
SELECT * FROM lambda_capacity_environments WHERE partition=? AND account=? AND region=? AND function_name=? AND version=? ORDER BY id;
-- name: ListAllCapacityEnvironments :many
SELECT * FROM lambda_capacity_environments ORDER BY id;
-- name: PutCapacityEnvironment :exec
INSERT INTO lambda_capacity_environments(id,partition,account,region,function_name,version,generation,guest_id,state,error,credentials_expire,modified) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,error=excluded.error,credentials_expire=excluded.credentials_expire,modified=excluded.modified;
-- name: DeleteCapacityEnvironment :exec
DELETE FROM lambda_capacity_environments WHERE id=?;
-- name: SetCapacityDeploymentState :exec
UPDATE lambda_functions SET state=?,state_reason=?,state_reason_code=?,revision=? WHERE partition=? AND account=? AND region=? AND name=? AND version=? AND deployment_revision=? AND pending=false;
