-- name: GetStore :one
SELECT * FROM identitystore_stores WHERE store_id=?;
-- name: PutStore :exec
INSERT INTO identitystore_stores(store_id,partition,account_id,region) VALUES(?,?,?,?);
-- name: GetUser :one
SELECT * FROM identitystore_users WHERE store_id=? AND id=?;
-- name: GetUserByName :one
SELECT * FROM identitystore_users WHERE store_id=? AND user_name=?;
-- name: ListUsers :many
SELECT * FROM identitystore_users WHERE store_id=? ORDER BY id;
-- name: PutUser :exec
INSERT INTO identitystore_users(store_id,id,user_name,display_name,name_formatted,name_family,name_given,name_middle,name_prefix,name_suffix,nick_name,profile_url,title,user_type,preferred_language,locale,timezone,birthdate,website)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(store_id,id) DO UPDATE SET user_name=excluded.user_name,display_name=excluded.display_name,name_formatted=excluded.name_formatted,name_family=excluded.name_family,name_given=excluded.name_given,name_middle=excluded.name_middle,name_prefix=excluded.name_prefix,name_suffix=excluded.name_suffix,nick_name=excluded.nick_name,profile_url=excluded.profile_url,title=excluded.title,user_type=excluded.user_type,preferred_language=excluded.preferred_language,locale=excluded.locale,timezone=excluded.timezone,birthdate=excluded.birthdate,website=excluded.website;
-- name: DeleteUser :exec
DELETE FROM identitystore_users WHERE store_id=? AND id=?;
-- name: ListEmails :many
SELECT * FROM identitystore_emails WHERE store_id=? AND user_id=? ORDER BY ordinal;
-- name: DeleteEmails :exec
DELETE FROM identitystore_emails WHERE store_id=? AND user_id=?;
-- name: PutEmail :exec
INSERT INTO identitystore_emails(store_id,user_id,ordinal,value,type,is_primary) VALUES(?,?,?,?,?,?);
-- name: GetGroup :one
SELECT * FROM identitystore_groups WHERE store_id=? AND id=?;
-- name: GetGroupByName :one
SELECT * FROM identitystore_groups WHERE store_id=? AND display_name=?;
-- name: ListGroups :many
SELECT * FROM identitystore_groups WHERE store_id=? ORDER BY id;
-- name: PutGroup :exec
INSERT INTO identitystore_groups(store_id,id,display_name,description,cloudformation_owner) VALUES(?,?,?,?,?)
ON CONFLICT(store_id,id) DO UPDATE SET display_name=excluded.display_name,description=excluded.description;
-- name: DeleteGroup :exec
DELETE FROM identitystore_groups WHERE store_id=? AND id=?;
-- name: GetMembership :one
SELECT * FROM identitystore_memberships WHERE store_id=? AND id=?;
-- name: GetMembershipFor :one
SELECT * FROM identitystore_memberships WHERE store_id=? AND user_id=? AND group_id=?;
-- name: ListMemberships :many
SELECT * FROM identitystore_memberships WHERE store_id=sqlc.arg(store_id) AND (user_id=sqlc.arg(user_id) OR sqlc.arg(user_id)='') AND (group_id=sqlc.arg(group_id) OR sqlc.arg(group_id)='') ORDER BY id;
-- name: PutMembership :exec
INSERT INTO identitystore_memberships(store_id,id,user_id,group_id,cloudformation_owner) VALUES(?,?,?,?,?);
-- name: DeleteMembership :exec
DELETE FROM identitystore_memberships WHERE store_id=? AND id=?;
-- name: DeleteStore :exec
DELETE FROM identitystore_stores WHERE store_id=?;
