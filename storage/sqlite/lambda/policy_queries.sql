-- name: GetFunctionPolicy :one
SELECT document,revision,owner_stack_id,owner_logical_id,owner_token FROM lambda_function_policies WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: PutFunctionPolicy :exec
INSERT INTO lambda_function_policies(partition,account,region,function_name,qualifier,document,revision,owner_stack_id,owner_logical_id,owner_token) VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,qualifier) DO UPDATE SET document=excluded.document,revision=excluded.revision,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;
-- name: DeleteFunctionPolicy :exec
DELETE FROM lambda_function_policies WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: GetFunctionPolicyPrincipals :many
SELECT principal,principal_id FROM lambda_function_policy_principals WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=? ORDER BY principal;
-- name: DeleteFunctionPolicyPrincipals :exec
DELETE FROM lambda_function_policy_principals WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: PutFunctionPolicyPrincipal :exec
INSERT INTO lambda_function_policy_principals(partition,account,region,function_name,qualifier,principal,principal_id) VALUES(?,?,?,?,?,?,?);
