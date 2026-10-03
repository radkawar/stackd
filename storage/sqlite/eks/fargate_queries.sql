-- name: GetFargateProfile :one
SELECT * FROM eks_fargate_profiles WHERE partition=? AND account_id=? AND region=? AND name=? AND profile_name=?;
-- name: ListFargateProfiles :many
SELECT * FROM eks_fargate_profiles WHERE partition=? AND account_id=? AND region=? AND name=? ORDER BY profile_name;
-- name: DeleteFargateProfile :exec
DELETE FROM eks_fargate_profiles WHERE partition=? AND account_id=? AND region=? AND name=? AND profile_name=?;
-- name: PutFargateProfile :exec
INSERT INTO eks_fargate_profiles(partition,account_id,region,name,profile_name,id,role_arn,role_id,status,operation,error,client_token,request_hash,selectors,subnets,tags,created,due,generation)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name,profile_name) DO UPDATE SET
id=excluded.id,role_arn=excluded.role_arn,role_id=excluded.role_id,status=excluded.status,operation=excluded.operation,error=excluded.error,client_token=excluded.client_token,request_hash=excluded.request_hash,selectors=excluded.selectors,subnets=excluded.subnets,tags=excluded.tags,created=excluded.created,due=excluded.due,generation=excluded.generation;
