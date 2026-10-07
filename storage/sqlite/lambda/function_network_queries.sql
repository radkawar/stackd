-- name: GetFunctionNetwork :one
SELECT * FROM lambda_function_networks WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;

-- name: PutFunctionNetwork :exec
INSERT INTO lambda_function_networks(partition,account,region,function_name,pending,version,incarnation,vpc_id)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET incarnation=excluded.incarnation,vpc_id=excluded.vpc_id;

-- name: ListFunctionNetworkMembers :many
SELECT * FROM lambda_function_network_members WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=? ORDER BY kind,position;

-- name: DeleteFunctionNetworkMembers :exec
DELETE FROM lambda_function_network_members WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;

-- name: PutFunctionNetworkMember :exec
INSERT INTO lambda_function_network_members(partition,account,region,function_name,pending,version,kind,position,resource_id) VALUES(?,?,?,?,?,?,?,?,?);
