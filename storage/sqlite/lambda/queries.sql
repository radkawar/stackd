-- name: GetFunction :one
SELECT * FROM lambda_functions WHERE partition=? AND account=? AND region=? AND name=? AND pending=? AND version=?;
-- name: ListFunctions :many
SELECT * FROM lambda_functions WHERE partition=? AND account=? AND region=? AND pending=false AND version=0 ORDER BY name;
-- name: ListAllFunctions :many
SELECT * FROM lambda_functions WHERE pending=? AND version=0 ORDER BY partition,account,region,name;
-- name: PutFunction :execrows
INSERT INTO lambda_functions(partition,account,region,name,pending,version,runtime,handler,role,description,architecture,code_size,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason,dead_letter_arn,deployment_revision,log_group,log_format,application_log_level,system_log_level,signing_profile_version_arn,signing_job_arn)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,name,pending,version) DO UPDATE SET runtime=excluded.runtime,handler=excluded.handler,role=excluded.role,description=excluded.description,architecture=excluded.architecture,code_size=excluded.code_size,code_sha256=excluded.code_sha256,timeout=excluded.timeout,memory_mb=excluded.memory_mb,ephemeral_mb=excluded.ephemeral_mb,revision=excluded.revision,modified=excluded.modified,state=excluded.state,state_reason=excluded.state_reason,state_reason_code=excluded.state_reason_code,update_status=excluded.update_status,update_reason=excluded.update_reason,dead_letter_arn=excluded.dead_letter_arn,deployment_revision=excluded.deployment_revision,log_group=excluded.log_group,log_format=excluded.log_format,application_log_level=excluded.application_log_level,system_log_level=excluded.system_log_level,signing_profile_version_arn=excluded.signing_profile_version_arn,signing_job_arn=excluded.signing_job_arn WHERE lambda_functions.version=0 OR lambda_functions.version=9223372036854775807;
-- name: DeleteFunction :exec
DELETE FROM lambda_functions WHERE partition=? AND account=? AND region=? AND name=?;
-- name: DeletePendingFunction :exec
DELETE FROM lambda_functions WHERE partition=? AND account=? AND region=? AND name=? AND pending=true AND version=0;
-- name: GetFunctionVariables :many
SELECT key,value FROM lambda_function_variables WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=? ORDER BY key;
-- name: DeleteFunctionVariables :exec
DELETE FROM lambda_function_variables WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionVariable :exec
INSERT INTO lambda_function_variables(partition,account,region,function_name,pending,version,key,value) VALUES(?,?,?,?,?,?,?,?);
-- name: GetFunctionTags :many
SELECT key,value FROM lambda_function_tags WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=0 ORDER BY key;
-- name: DeleteFunctionTags :exec
DELETE FROM lambda_function_tags WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=0;
-- name: PutFunctionTag :exec
INSERT INTO lambda_function_tags(partition,account,region,function_name,pending,key,value) VALUES(?,?,?,?,?,?,?);
-- name: ListFunctionVersions :many
SELECT * FROM lambda_functions WHERE partition=? AND account=? AND region=? AND name=? AND version>0 ORDER BY version;
-- name: DeleteFunctionVersion :exec
DELETE FROM lambda_functions WHERE partition=? AND account=? AND region=? AND name=? AND version=? AND version>0;
-- name: SetPublishedDeploymentState :exec
UPDATE lambda_functions SET state=?,state_reason=?,state_reason_code=?,update_status=?,update_reason=?,revision=? WHERE partition=? AND account=? AND region=? AND name=? AND deployment_revision=? AND version>0;
-- name: LastAllocatedVersion :one
SELECT last_version FROM lambda_version_allocations WHERE partition=? AND account=? AND region=? AND function_name=?;
-- name: AllocateFunctionVersion :one
INSERT INTO lambda_version_allocations(partition,account,region,function_name,last_version) VALUES(?,?,?,?,1)
ON CONFLICT(partition,account,region,function_name) DO UPDATE SET last_version=last_version+1 WHERE last_version<9223372036854775807 RETURNING last_version;
-- name: GetAlias :one
SELECT * FROM lambda_aliases WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: ListAliases :many
SELECT * FROM lambda_aliases WHERE partition=? AND account=? AND region=? AND function_name=? ORDER BY qualifier;
-- name: PutAlias :exec
INSERT INTO lambda_aliases(partition,account,region,function_name,qualifier,function_version,additional_version,additional_weight,description,revision,owner_stack_id,owner_logical_id,owner_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,qualifier) DO UPDATE SET function_version=excluded.function_version,additional_version=excluded.additional_version,additional_weight=excluded.additional_weight,description=excluded.description,revision=excluded.revision,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;
-- name: DeleteAlias :exec
DELETE FROM lambda_aliases WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
