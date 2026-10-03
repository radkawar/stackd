-- name: GetPodIdentityAssociation :one
SELECT * FROM eks_pod_identity_association WHERE partition=? AND account_id=? AND region=? AND name=? AND id=?;

-- name: ListPodIdentityAssociations :many
SELECT * FROM eks_pod_identity_association WHERE partition=? AND account_id=? AND region=? AND name=? ORDER BY id;

-- name: PutPodIdentityAssociation :exec
INSERT INTO eks_pod_identity_association (partition,account_id,region,name,id,cluster_id,namespace,service_account,role_arn,role_id,target_role_arn,target_role_id,external_id,owner_arn,policy,disable_session_tags,tags,created,modified,client_token)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,name,id) DO UPDATE SET
 cluster_id=excluded.cluster_id,
 namespace=excluded.namespace,
 service_account=excluded.service_account,
 role_arn=excluded.role_arn,
 role_id=excluded.role_id,
 target_role_arn=excluded.target_role_arn,
 target_role_id=excluded.target_role_id,
 external_id=excluded.external_id,
 owner_arn=excluded.owner_arn,
 policy=excluded.policy,
 disable_session_tags=excluded.disable_session_tags,
 tags=excluded.tags,
 created=excluded.created,
 modified=excluded.modified,
 client_token=excluded.client_token;

-- name: DeletePodIdentityAssociation :exec
DELETE FROM eks_pod_identity_association WHERE partition=? AND account_id=? AND region=? AND name=? AND id=?;

-- name: DeleteClusterPodIdentityAssociations :exec
DELETE FROM eks_pod_identity_association WHERE partition=? AND account_id=? AND region=? AND name=?;
