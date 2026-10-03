-- name: GetIdentity :one
SELECT * FROM sesv2_identities WHERE arn=?;
-- name: GetIdentityByToken :one
SELECT * FROM sesv2_identities WHERE verification_token=? AND verification_token<>'';
-- name: ListIdentities :many
SELECT * FROM sesv2_identities WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: PutIdentity :exec
INSERT INTO sesv2_identities(arn,partition,account_id,region,name,verified,verification_token,verification_expires,configuration_set) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET verified=excluded.verified,verification_token=excluded.verification_token,verification_expires=excluded.verification_expires,configuration_set=excluded.configuration_set;
-- name: DeleteIdentity :exec
DELETE FROM sesv2_identities WHERE arn=?;
-- name: ListIdentityTags :many
SELECT key,value FROM sesv2_identity_tags WHERE arn=? ORDER BY key;
-- name: DeleteIdentityTags :exec
DELETE FROM sesv2_identity_tags WHERE arn=?;
-- name: PutIdentityTag :exec
INSERT INTO sesv2_identity_tags(arn,key,value) VALUES(?,?,?);
-- name: ListIdentityPolicies :many
SELECT name,document FROM sesv2_identity_policies WHERE arn=? ORDER BY name;
-- name: ListIdentityPolicyPrincipals :many
SELECT policy_name,principal_arn,principal_id FROM sesv2_identity_policy_principals WHERE arn=? ORDER BY policy_name,principal_arn;
-- name: DeleteIdentityPolicies :exec
DELETE FROM sesv2_identity_policies WHERE arn=?;
-- name: PutIdentityPolicy :exec
INSERT INTO sesv2_identity_policies(arn,name,document) VALUES(?,?,?);
-- name: PutIdentityPolicyPrincipal :exec
INSERT INTO sesv2_identity_policy_principals(arn,policy_name,principal_arn,principal_id) VALUES(?,?,?,?);
-- name: GetTemplate :one
SELECT * FROM sesv2_templates WHERE arn=?;
-- name: ListTemplates :many
SELECT * FROM sesv2_templates WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: PutTemplate :exec
INSERT INTO sesv2_templates(arn,partition,account_id,region,name,subject,text_body,html_body,created) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET subject=excluded.subject,text_body=excluded.text_body,html_body=excluded.html_body;
-- name: DeleteTemplate :exec
DELETE FROM sesv2_templates WHERE arn=?;
-- name: GetConfigurationSet :one
SELECT * FROM sesv2_configuration_sets WHERE arn=?;
-- name: ListConfigurationSets :many
SELECT * FROM sesv2_configuration_sets WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: PutConfigurationSet :exec
INSERT INTO sesv2_configuration_sets(arn,partition,account_id,region,name,sending_enabled) VALUES(?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET sending_enabled=excluded.sending_enabled;
-- name: DeleteConfigurationSet :exec
DELETE FROM sesv2_configuration_sets WHERE arn=?;
-- name: ListConfigurationTags :many
SELECT key,value FROM sesv2_configuration_tags WHERE arn=? ORDER BY key;
-- name: DeleteConfigurationTags :exec
DELETE FROM sesv2_configuration_tags WHERE arn=?;
-- name: PutConfigurationTag :exec
INSERT INTO sesv2_configuration_tags(arn,key,value) VALUES(?,?,?);
-- name: GetAccount :one
SELECT * FROM sesv2_accounts WHERE partition=? AND account_id=? AND region=?;
-- name: PutAccount :exec
INSERT INTO sesv2_accounts(partition,account_id,region,sending_enabled) VALUES(?,?,?,?) ON CONFLICT(partition,account_id,region) DO UPDATE SET sending_enabled=excluded.sending_enabled;
-- name: GetMessage :one
SELECT * FROM sesv2_messages WHERE arn=?;
-- name: ListMessages :many
SELECT * FROM sesv2_messages WHERE partition=? AND account_id=? AND region=? ORDER BY id;
-- name: NextCapture :one
SELECT * FROM sesv2_messages WHERE capture_pending=1 ORDER BY due,arn LIMIT 1;
-- name: PutMessage :exec
INSERT INTO sesv2_messages(arn,partition,account_id,region,id,sender,feedback,subject,text_body,html_body,content_kind,template_name,template_data,configuration_set,mime,accepted,due,capture_pending,capture_error,source_identity_arn) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET due=excluded.due,capture_pending=excluded.capture_pending,capture_error=excluded.capture_error;
-- name: ListMessageAddresses :many
SELECT kind,position,address FROM sesv2_message_addresses WHERE arn=? ORDER BY kind,position;
-- name: DeleteMessageAddresses :exec
DELETE FROM sesv2_message_addresses WHERE arn=?;
-- name: PutMessageAddress :exec
INSERT INTO sesv2_message_addresses(arn,kind,position,address) VALUES(?,?,?,?);
-- name: ListMessageTags :many
SELECT key,value FROM sesv2_message_tags WHERE arn=? ORDER BY key;
-- name: DeleteMessageTags :exec
DELETE FROM sesv2_message_tags WHERE arn=?;
-- name: PutMessageTag :exec
INSERT INTO sesv2_message_tags(arn,key,value) VALUES(?,?,?);
