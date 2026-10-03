-- name: GetCodeSigningConfig :one
SELECT * FROM lambda_code_signing_configs WHERE partition=? AND account=? AND region=? AND id=?;
-- name: ListCodeSigningConfigs :many
SELECT * FROM lambda_code_signing_configs WHERE partition=? AND account=? AND region=? ORDER BY id;
-- name: PutCodeSigningConfig :exec
INSERT INTO lambda_code_signing_configs(partition,account,region,id,description,policy,modified) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,id) DO UPDATE SET description=excluded.description,policy=excluded.policy,modified=excluded.modified;
-- name: DeleteCodeSigningConfig :exec
DELETE FROM lambda_code_signing_configs WHERE partition=? AND account=? AND region=? AND id=?;
-- name: GetCodeSigningPublishers :many
SELECT profile_version_arn FROM lambda_code_signing_publishers WHERE partition=? AND account=? AND region=? AND config_id=? ORDER BY position;
-- name: DeleteCodeSigningPublishers :exec
DELETE FROM lambda_code_signing_publishers WHERE partition=? AND account=? AND region=? AND config_id=?;
-- name: PutCodeSigningPublisher :exec
INSERT INTO lambda_code_signing_publishers(partition,account,region,config_id,position,profile_version_arn) VALUES(?,?,?,?,?,?);
-- name: GetCodeSigningTags :many
SELECT key,value FROM lambda_code_signing_tags WHERE partition=? AND account=? AND region=? AND config_id=? ORDER BY key;
-- name: DeleteCodeSigningTags :exec
DELETE FROM lambda_code_signing_tags WHERE partition=? AND account=? AND region=? AND config_id=?;
-- name: PutCodeSigningTag :exec
INSERT INTO lambda_code_signing_tags(partition,account,region,config_id,key,value) VALUES(?,?,?,?,?,?);
-- name: GetFunctionCodeSigningConfig :one
SELECT config_id FROM lambda_function_code_signing_configs WHERE partition=? AND account=? AND region=? AND function_name=?;
-- name: ListFunctionsByCodeSigningConfig :many
SELECT function_name FROM lambda_function_code_signing_configs WHERE partition=? AND account=? AND region=? AND config_id=? ORDER BY function_name;
-- name: PutFunctionCodeSigningConfig :exec
INSERT INTO lambda_function_code_signing_configs(partition,account,region,function_name,config_id) VALUES(?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name) DO UPDATE SET config_id=excluded.config_id;
-- name: DeleteFunctionCodeSigningConfig :exec
DELETE FROM lambda_function_code_signing_configs WHERE partition=? AND account=? AND region=? AND function_name=?;
