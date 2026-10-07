-- name: GetCertificate :one
SELECT * FROM acm_certificates WHERE arn = ?;
-- name: GetCertificateByOwner :one
SELECT * FROM acm_certificates WHERE partition=? AND account_id=? AND region=? AND cfn_owner=? AND cfn_owner<>'';
-- name: ListCertificates :many
SELECT * FROM acm_certificates ORDER BY arn;
-- name: DeleteCertificate :exec
DELETE FROM acm_certificates WHERE arn = ?;
-- name: PutCertificate :exec
INSERT INTO acm_certificates(arn,partition,account_id,region,id,domain,status,type,key_algorithm,transparency,export_option,created,issued,imported,not_before,not_after,validation_deadline,next_check,renewal_updated,version,material_version,renewal_status,exported,certificate_pem,chain_pem,private_key_pem,cfn_owner)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET domain=excluded.domain,status=excluded.status,key_algorithm=excluded.key_algorithm,transparency=excluded.transparency,export_option=excluded.export_option,issued=excluded.issued,imported=excluded.imported,not_before=excluded.not_before,not_after=excluded.not_after,validation_deadline=excluded.validation_deadline,next_check=excluded.next_check,renewal_updated=excluded.renewal_updated,version=excluded.version,material_version=excluded.material_version,renewal_status=excluded.renewal_status,exported=excluded.exported,certificate_pem=excluded.certificate_pem,chain_pem=excluded.chain_pem,private_key_pem=excluded.private_key_pem;
-- name: ListValidations :many
SELECT * FROM acm_validations WHERE certificate_arn = ? ORDER BY position;
-- name: DeleteValidations :exec
DELETE FROM acm_validations WHERE certificate_arn = ?;
-- name: PutValidation :exec
INSERT INTO acm_validations(certificate_arn,position,domain,name,value,status) VALUES (?,?,?,?,?,?);
-- name: ListTags :many
SELECT * FROM acm_tags WHERE certificate_arn = ? ORDER BY key;
-- name: DeleteTags :exec
DELETE FROM acm_tags WHERE certificate_arn = ?;
-- name: PutTag :exec
INSERT INTO acm_tags(certificate_arn,key,value) VALUES (?,?,?);
-- name: GetToken :one
SELECT * FROM acm_validation_tokens WHERE partition = ? AND account_id = ? AND domain = ?;
-- name: PutToken :exec
INSERT INTO acm_validation_tokens(partition,account_id,domain,name,value) VALUES (?,?,?,?,?) ON CONFLICT(partition,account_id,domain) DO UPDATE SET name=excluded.name,value=excluded.value;
-- name: GetAuthority :one
SELECT certificate_pem,private_key_pem FROM acm_authority WHERE singleton = 1;
-- name: PutAuthority :exec
INSERT INTO acm_authority(singleton,certificate_pem,private_key_pem) VALUES (1,?,?) ON CONFLICT(singleton) DO UPDATE SET certificate_pem=excluded.certificate_pem,private_key_pem=excluded.private_key_pem;
-- name: GetReceipt :one
SELECT * FROM acm_request_receipts WHERE partition = ? AND account_id = ? AND region = ? AND token = ?;
-- name: PutReceipt :exec
INSERT INTO acm_request_receipts(partition,account_id,region,token,arn,expires) VALUES (?,?,?,?,?,?) ON CONFLICT(partition,account_id,region,token) DO UPDATE SET arn=excluded.arn,expires=excluded.expires;
-- name: GetCertificateState :one
SELECT partition, account_id, region, id, status, not_before, not_after, material_version FROM acm_certificates WHERE arn = ?;
