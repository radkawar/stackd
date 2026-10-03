-- name: GetPool :one
SELECT * FROM cognitoidentity_pools WHERE partition=? AND account_id=? AND region=? AND pool_id=?;
-- name: PoolByID :one
SELECT * FROM cognitoidentity_pools WHERE partition=? AND region=? AND pool_id=?;
-- name: ListPools :many
SELECT * FROM cognitoidentity_pools WHERE partition=? AND account_id=? AND region=? ORDER BY pool_id;
-- name: PutPool :exec
INSERT INTO cognitoidentity_pools(partition,account_id,region,pool_id,name,allow_unauthenticated,allow_classic,providers,tags,roles,mappings,principal_tag_maps) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,pool_id) DO UPDATE SET name=excluded.name,allow_unauthenticated=excluded.allow_unauthenticated,allow_classic=excluded.allow_classic,providers=excluded.providers,tags=excluded.tags,roles=excluded.roles,mappings=excluded.mappings,principal_tag_maps=excluded.principal_tag_maps;
-- name: DeletePool :exec
DELETE FROM cognitoidentity_pools WHERE partition=? AND account_id=? AND region=? AND pool_id=?;
-- name: GetIdentity :one
SELECT * FROM cognitoidentity_identities WHERE partition=? AND region=? AND identity_id=?;
-- name: IdentityByLogin :one
SELECT i.* FROM cognitoidentity_identities i JOIN cognitoidentity_logins l ON i.partition=l.partition AND i.region=l.region AND i.identity_id=l.identity_id WHERE l.partition=? AND l.region=? AND l.pool_id=? AND l.provider=? AND l.subject=?;
-- name: ListIdentities :many
SELECT * FROM cognitoidentity_identities WHERE partition=? AND account_id=? AND region=? AND pool_id=? ORDER BY identity_id;
-- name: PutIdentity :exec
INSERT INTO cognitoidentity_identities(partition,account_id,region,pool_id,identity_id,created,modified) VALUES(?,?,?,?,?,?,?) ON CONFLICT(partition,region,identity_id) DO UPDATE SET modified=excluded.modified;
-- name: DeleteIdentity :exec
DELETE FROM cognitoidentity_identities WHERE partition=? AND region=? AND identity_id=?;
-- name: ListLogins :many
SELECT provider,subject FROM cognitoidentity_logins WHERE partition=? AND region=? AND identity_id=? ORDER BY provider,subject;
-- name: DeleteLogins :exec
DELETE FROM cognitoidentity_logins WHERE partition=? AND region=? AND identity_id=?;
-- name: PutLogin :exec
INSERT INTO cognitoidentity_logins(partition,region,pool_id,identity_id,provider,subject) VALUES(?,?,?,?,?,?);
