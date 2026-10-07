-- name: GetCloudFormationCreation :one
SELECT * FROM eks_cloudformation_creations WHERE partition = ? AND account_id = ? AND region = ? AND resource_type = ? AND owner = ?;

-- name: ListCloudFormationCreations :many
SELECT * FROM eks_cloudformation_creations WHERE partition = ? AND account_id = ? AND region = ? ORDER BY resource_type, owner;

-- name: PutCloudFormationCreation :exec
INSERT INTO eks_cloudformation_creations (partition, account_id, region, resource_type, owner, cluster_name, native_name, native_id, physical_id, arn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
