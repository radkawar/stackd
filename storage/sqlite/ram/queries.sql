-- cloudformation_owner is fixed at creation and never changed by an upsert.
-- name: PutShare :exec
INSERT INTO ram_shares (arn,partition,account_id,region,name,status,feature_set,policy_id,allow_external,retain_on_leave,created,updated,cloudformation_owner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,name=excluded.name,status=excluded.status,feature_set=excluded.feature_set,policy_id=excluded.policy_id,allow_external=excluded.allow_external,retain_on_leave=excluded.retain_on_leave,created=excluded.created,updated=excluded.updated;

-- name: GetShare :one
SELECT * FROM ram_shares WHERE arn=?;

-- name: ListShares :many
SELECT * FROM ram_shares ORDER BY arn;

-- name: PutShareTag :exec
INSERT INTO ram_share_tags (share_arn,key,value) VALUES (?,?,?)
ON CONFLICT(share_arn,key) DO UPDATE SET value=excluded.value;

-- name: ListShareTags :many
SELECT * FROM ram_share_tags WHERE share_arn=? ORDER BY key;

-- name: DeleteShareTags :exec
DELETE FROM ram_share_tags WHERE share_arn=?;

-- name: PutResource :exec
INSERT INTO ram_resources (share_arn,position,arn,resource_type,partition,account_id,region,organization_only,supports_iam_principals,status,status_message,created,updated,cloudformation_owner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(share_arn,position) DO UPDATE SET arn=excluded.arn,resource_type=excluded.resource_type,partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,organization_only=excluded.organization_only,supports_iam_principals=excluded.supports_iam_principals,status=excluded.status,status_message=excluded.status_message,created=excluded.created,updated=excluded.updated,cloudformation_owner=excluded.cloudformation_owner;

-- name: ListResources :many
SELECT * FROM ram_resources WHERE share_arn=? ORDER BY position;

-- name: DeleteResources :exec
DELETE FROM ram_resources WHERE share_arn=?;

-- name: PutPrincipal :exec
INSERT INTO ram_principals (share_arn,position,principal,principal_id,status,invitation_arn,organization,created,updated,cloudformation_owner) VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(share_arn,position) DO UPDATE SET principal=excluded.principal,principal_id=excluded.principal_id,status=excluded.status,invitation_arn=excluded.invitation_arn,organization=excluded.organization,created=excluded.created,updated=excluded.updated,cloudformation_owner=excluded.cloudformation_owner;

-- name: ListPrincipals :many
SELECT * FROM ram_principals WHERE share_arn=? ORDER BY position;

-- name: DeletePrincipals :exec
DELETE FROM ram_principals WHERE share_arn=?;

-- name: PutSharePermission :exec
INSERT INTO ram_share_permissions (share_arn,position,arn,resource_type,version,cloudformation_owner) VALUES (?,?,?,?,?,?)
ON CONFLICT(share_arn,position) DO UPDATE SET arn=excluded.arn,resource_type=excluded.resource_type,version=excluded.version,cloudformation_owner=excluded.cloudformation_owner;

-- name: ListSharePermissions :many
SELECT * FROM ram_share_permissions WHERE share_arn=? ORDER BY position;

-- name: DeleteSharePermissions :exec
DELETE FROM ram_share_permissions WHERE share_arn=?;

-- name: PutInvitation :exec
INSERT INTO ram_invitations (arn,partition,account_id,region,share_arn,share_name,sender,receiver,status,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,share_arn=excluded.share_arn,share_name=excluded.share_name,sender=excluded.sender,receiver=excluded.receiver,status=excluded.status,created=excluded.created,updated=excluded.updated;

-- name: GetInvitation :one
SELECT * FROM ram_invitations WHERE arn=?;

-- name: ListInvitations :many
SELECT * FROM ram_invitations ORDER BY arn;

-- name: PutPermission :exec
INSERT INTO ram_permissions (arn,partition,account_id,region,name,resource_type,type,feature_set,status,resource_type_default,default_version,created,updated,cloudformation_owner,object_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,name=excluded.name,resource_type=excluded.resource_type,type=excluded.type,feature_set=excluded.feature_set,status=excluded.status,resource_type_default=excluded.resource_type_default,default_version=excluded.default_version,created=excluded.created,updated=excluded.updated,cloudformation_owner=CASE WHEN ram_permissions.object_id<>excluded.object_id THEN excluded.cloudformation_owner ELSE ram_permissions.cloudformation_owner END,object_id=excluded.object_id;

-- name: GetPermission :one
SELECT * FROM ram_permissions WHERE arn=?;

-- name: ListPermissions :many
SELECT * FROM ram_permissions ORDER BY arn;

-- name: PutPermissionTag :exec
INSERT INTO ram_permission_tags (permission_arn,key,value) VALUES (?,?,?)
ON CONFLICT(permission_arn,key) DO UPDATE SET value=excluded.value;

-- name: ListPermissionTags :many
SELECT * FROM ram_permission_tags WHERE permission_arn=? ORDER BY key;

-- name: DeletePermissionTags :exec
DELETE FROM ram_permission_tags WHERE permission_arn=?;

-- name: PutPermissionVersion :exec
INSERT INTO ram_permission_versions (permission_arn,version,document,created,updated,deleted) VALUES (?,?,?,?,?,?)
ON CONFLICT(permission_arn,version) DO UPDATE SET document=excluded.document,created=excluded.created,updated=excluded.updated,deleted=excluded.deleted;

-- name: ListPermissionVersions :many
SELECT * FROM ram_permission_versions WHERE permission_arn=? ORDER BY version;

-- name: DeletePermissionVersions :exec
DELETE FROM ram_permission_versions WHERE permission_arn=?;

-- name: PutPermissionAction :exec
INSERT INTO ram_permission_actions (permission_arn,version,position,action) VALUES (?,?,?,?)
ON CONFLICT(permission_arn,version,position) DO UPDATE SET action=excluded.action;

-- name: ListPermissionActions :many
SELECT * FROM ram_permission_actions WHERE permission_arn=? ORDER BY version,position;

-- name: DeletePermissionActions :exec
DELETE FROM ram_permission_actions WHERE permission_arn=?;

-- name: PutReceipt :exec
INSERT INTO ram_receipts (partition,account_id,region,operation,token,hash,arn,version,cloudformation_owner,object_id) VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,operation,token) DO UPDATE SET hash=excluded.hash,arn=excluded.arn,version=excluded.version;

-- name: GetReceipt :one
SELECT * FROM ram_receipts WHERE partition=? AND account_id=? AND region=? AND operation=? AND token=?;

-- name: PutReplacement :exec
INSERT INTO ram_replacements (id,partition,account_id,region,from_arn,to_arn,status,from_version,to_version,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,from_arn=excluded.from_arn,to_arn=excluded.to_arn,status=excluded.status,from_version=excluded.from_version,to_version=excluded.to_version,created=excluded.created,updated=excluded.updated;

-- name: ListReplacements :many
SELECT * FROM ram_replacements ORDER BY id;

-- name: DeletePermission :exec
DELETE FROM ram_permissions WHERE arn=?;
