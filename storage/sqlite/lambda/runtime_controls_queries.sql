-- name: GetRecursiveLoop :one
SELECT recursive_loop FROM lambda_recursion_controls WHERE partition=? AND account=? AND region=? AND function_name=?;
-- name: PutRecursiveLoop :exec
INSERT INTO lambda_recursion_controls(partition,account,region,function_name,recursive_loop) VALUES(?,?,?,?,?) ON CONFLICT(partition,account,region,function_name) DO UPDATE SET recursive_loop=excluded.recursive_loop;
-- name: GetRuntimeManagement :one
SELECT update_runtime_on FROM lambda_runtime_management WHERE partition=? AND account=? AND region=? AND function_name=? AND version=?;
-- name: PutRuntimeManagement :exec
INSERT INTO lambda_runtime_management(partition,account,region,function_name,version,update_runtime_on) VALUES(?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,version) DO UPDATE SET update_runtime_on=excluded.update_runtime_on;
-- name: DeleteRuntimeManagement :exec
DELETE FROM lambda_runtime_management WHERE partition=? AND account=? AND region=? AND function_name=? AND version=?;
-- name: GetProvisionedConcurrency :one
SELECT * FROM lambda_provisioned_concurrency WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: ListProvisionedConcurrency :many
SELECT * FROM lambda_provisioned_concurrency ORDER BY partition,account,region,function_name,qualifier;
-- name: PutProvisionedConcurrency :exec
INSERT INTO lambda_provisioned_concurrency(partition,account,region,function_name,qualifier,requested,generation,status,status_reason,modified) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,qualifier) DO UPDATE SET requested=excluded.requested,generation=excluded.generation,status=excluded.status,status_reason=excluded.status_reason,modified=excluded.modified;
-- name: DeleteProvisionedConcurrency :exec
DELETE FROM lambda_provisioned_concurrency WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
