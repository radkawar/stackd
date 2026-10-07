-- name: GetFunctionOwner :one
SELECT stack_id,logical_id,token FROM lambda_function_owners WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionOwner :exec
INSERT INTO lambda_function_owners(partition,account,region,function_name,pending,version,stack_id,logical_id,token) VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET stack_id=excluded.stack_id,logical_id=excluded.logical_id,token=excluded.token;
-- name: DeleteFunctionOwner :exec
DELETE FROM lambda_function_owners WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
