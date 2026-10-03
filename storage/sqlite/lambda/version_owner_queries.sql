-- name: GetOwnedFunctionVersion :one
SELECT version FROM lambda_version_owners WHERE partition=? AND account=? AND region=? AND function_name=? AND owner_stack_id=? AND owner_logical_id=? AND owner_token=?;
-- name: GetFunctionVersionOwner :one
SELECT owner_stack_id,owner_logical_id,owner_token FROM lambda_version_owners WHERE partition=? AND account=? AND region=? AND function_name=? AND version=?;
-- name: PutFunctionVersionOwner :exec
INSERT INTO lambda_version_owners(partition,account,region,function_name,version,owner_stack_id,owner_logical_id,owner_token) VALUES(?,?,?,?,?,?,?,?);
