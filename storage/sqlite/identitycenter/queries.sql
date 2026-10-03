-- name: GetInstance :one
SELECT * FROM identitycenter_instances WHERE arn=?;

-- name: ListInstances :many
SELECT * FROM identitycenter_instances WHERE partition=? AND account_id=? AND region=? ORDER BY arn;

-- name: PutInstance :exec
INSERT INTO identitycenter_instances (arn,partition,account_id,region,store_id,name,client_token,created) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,store_id=excluded.store_id,name=excluded.name,client_token=excluded.client_token,created=excluded.created;

-- name: DeleteInstance :exec
DELETE FROM identitycenter_instances WHERE arn=?;

-- name: ListInstanceTags :many
SELECT * FROM identitycenter_instance_tags WHERE instance_arn=? ORDER BY key;

-- name: DeleteInstanceTags :exec
DELETE FROM identitycenter_instance_tags WHERE instance_arn=?;

-- name: PutInstanceTag :exec
INSERT INTO identitycenter_instance_tags (instance_arn,key,value) VALUES (?,?,?);

-- name: GetPermissionSet :one
SELECT * FROM identitycenter_permission_sets WHERE arn=?;

-- name: ListPermissionSets :many
SELECT * FROM identitycenter_permission_sets WHERE instance_arn=? ORDER BY arn;

-- name: PutPermissionSet :exec
INSERT INTO identitycenter_permission_sets (arn,instance_arn,name,description,relay_state,inline_policy,duration_ns,created,boundary_arn,boundary_name,boundary_path) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET instance_arn=excluded.instance_arn,name=excluded.name,description=excluded.description,relay_state=excluded.relay_state,inline_policy=excluded.inline_policy,duration_ns=excluded.duration_ns,created=excluded.created,boundary_arn=excluded.boundary_arn,boundary_name=excluded.boundary_name,boundary_path=excluded.boundary_path;

-- name: DeletePermissionSet :exec
DELETE FROM identitycenter_permission_sets WHERE arn=?;

-- name: ListPermissionSetTags :many
SELECT * FROM identitycenter_permission_set_tags WHERE permission_set_arn=? ORDER BY key;

-- name: DeletePermissionSetTags :exec
DELETE FROM identitycenter_permission_set_tags WHERE permission_set_arn=?;

-- name: PutPermissionSetTag :exec
INSERT INTO identitycenter_permission_set_tags (permission_set_arn,key,value) VALUES (?,?,?);

-- name: ListManagedPolicies :many
SELECT * FROM identitycenter_managed_policies WHERE permission_set_arn=? ORDER BY position;

-- name: DeleteManagedPolicies :exec
DELETE FROM identitycenter_managed_policies WHERE permission_set_arn=?;

-- name: PutManagedPolicy :exec
INSERT INTO identitycenter_managed_policies (permission_set_arn,position,arn) VALUES (?,?,?);

-- name: ListCustomerManagedPolicies :many
SELECT * FROM identitycenter_customer_managed_policies WHERE permission_set_arn=? ORDER BY position;

-- name: DeleteCustomerManagedPolicies :exec
DELETE FROM identitycenter_customer_managed_policies WHERE permission_set_arn=?;

-- name: PutCustomerManagedPolicy :exec
INSERT INTO identitycenter_customer_managed_policies (permission_set_arn,position,name,path) VALUES (?,?,?,?);

-- name: ListAssignments :many
SELECT * FROM identitycenter_assignments WHERE instance_arn=? ORDER BY permission_set_arn,account_id,principal_type,principal_id;

-- name: PutAssignment :exec
INSERT INTO identitycenter_assignments (instance_arn,permission_set_arn,account_id,principal_type,principal_id) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING;

-- name: DeleteAssignment :exec
DELETE FROM identitycenter_assignments WHERE instance_arn=? AND permission_set_arn=? AND account_id=? AND principal_type=? AND principal_id=?;

-- name: ListProvisionings :many
SELECT * FROM identitycenter_provisionings WHERE instance_arn=? ORDER BY permission_set_arn,account_id;

-- name: PutProvisioning :exec
INSERT INTO identitycenter_provisionings (instance_arn,permission_set_arn,account_id,role_arn,role_id,role_name) VALUES (?,?,?,?,?,?)
ON CONFLICT(permission_set_arn,account_id) DO UPDATE SET instance_arn=excluded.instance_arn,role_arn=excluded.role_arn,role_id=excluded.role_id,role_name=excluded.role_name;

-- name: DeleteProvisioning :exec
DELETE FROM identitycenter_provisionings WHERE permission_set_arn=? AND account_id=?;

-- name: GetOperation :one
SELECT * FROM identitycenter_operations WHERE id=?;

-- name: ListOperations :many
SELECT * FROM identitycenter_operations WHERE instance_arn=? ORDER BY id;

-- name: PutOperation :exec
INSERT INTO identitycenter_operations (id,instance_arn,kind,permission_set_arn,account_id,principal_type,principal_id,created) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET instance_arn=excluded.instance_arn,kind=excluded.kind,permission_set_arn=excluded.permission_set_arn,account_id=excluded.account_id,principal_type=excluded.principal_type,principal_id=excluded.principal_id,created=excluded.created;

-- name: GetClient :one
SELECT * FROM identitycenter_clients WHERE id=?;

-- name: PutClient :exec
INSERT INTO identitycenter_clients (id,secret_hash,name,region,partition,created,expires,issuer_url) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET secret_hash=excluded.secret_hash,name=excluded.name,region=excluded.region,partition=excluded.partition,created=excluded.created,expires=excluded.expires,issuer_url=excluded.issuer_url;

-- name: ListClientScopes :many
SELECT * FROM identitycenter_client_scopes WHERE client_id=? ORDER BY position;

-- name: DeleteClientScopes :exec
DELETE FROM identitycenter_client_scopes WHERE client_id=?;

-- name: PutClientScope :exec
INSERT INTO identitycenter_client_scopes (client_id,position,scope) VALUES (?,?,?);

-- name: GetDevice :one
SELECT * FROM identitycenter_devices WHERE code_hash=?;

-- name: GetDeviceByUserCode :one
SELECT * FROM identitycenter_devices WHERE user_code=? ORDER BY code_hash LIMIT 1;

-- name: PutDevice :exec
INSERT INTO identitycenter_devices (code_hash,user_code,client_id,instance_arn,user_id,csrf,state,created,expires,last_poll,interval) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(code_hash) DO UPDATE SET user_code=excluded.user_code,client_id=excluded.client_id,instance_arn=excluded.instance_arn,user_id=excluded.user_id,csrf=excluded.csrf,state=excluded.state,created=excluded.created,expires=excluded.expires,last_poll=excluded.last_poll,interval=excluded.interval;

-- name: GetSessionByAccess :one
SELECT * FROM identitycenter_sessions WHERE access_hash=? ORDER BY id LIMIT 1;

-- name: GetSessionByRefresh :one
SELECT * FROM identitycenter_sessions WHERE refresh_hash=? ORDER BY id LIMIT 1;

-- name: PutSession :exec
INSERT INTO identitycenter_sessions (id,family_id,client_id,instance_arn,user_id,access_hash,refresh_hash,created,access_expires,refresh_expires,revoked) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET family_id=excluded.family_id,client_id=excluded.client_id,instance_arn=excluded.instance_arn,user_id=excluded.user_id,access_hash=excluded.access_hash,refresh_hash=excluded.refresh_hash,created=excluded.created,access_expires=excluded.access_expires,refresh_expires=excluded.refresh_expires,revoked=excluded.revoked;

-- name: ListSessions :many
SELECT * FROM identitycenter_sessions WHERE family_id=? ORDER BY id;

-- name: ListClientGrantTypes :many
SELECT * FROM identitycenter_client_grant_types WHERE client_id=? ORDER BY position;

-- name: DeleteClientGrantTypes :exec
DELETE FROM identitycenter_client_grant_types WHERE client_id=?;

-- name: PutClientGrantType :exec
INSERT INTO identitycenter_client_grant_types (client_id,position,grant_type) VALUES (?,?,?);

-- name: ListClientRedirectURIs :many
SELECT * FROM identitycenter_client_redirect_uris WHERE client_id=? ORDER BY position;

-- name: DeleteClientRedirectURIs :exec
DELETE FROM identitycenter_client_redirect_uris WHERE client_id=?;

-- name: PutClientRedirectURI :exec
INSERT INTO identitycenter_client_redirect_uris (client_id,position,uri) VALUES (?,?,?);

-- name: GetAuthorization :one
SELECT * FROM identitycenter_authorizations WHERE id=?;

-- name: GetAuthorizationByCode :one
SELECT * FROM identitycenter_authorizations WHERE code_hash=?;

-- name: PutAuthorization :exec
INSERT INTO identitycenter_authorizations (id,code_hash,client_id,instance_arn,user_id,redirect_uri,challenge,scope,oauth_state,csrf,state,created,expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET code_hash=excluded.code_hash,client_id=excluded.client_id,instance_arn=excluded.instance_arn,user_id=excluded.user_id,redirect_uri=excluded.redirect_uri,challenge=excluded.challenge,scope=excluded.scope,oauth_state=excluded.oauth_state,csrf=excluded.csrf,state=excluded.state,created=excluded.created,expires=excluded.expires;
