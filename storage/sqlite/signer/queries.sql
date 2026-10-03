-- name: GetAuthority :one
SELECT * FROM signer_authorities WHERE partition=? AND account_id=? AND region=?;
-- name: ListAuthorities :many
SELECT * FROM signer_authorities ORDER BY partition,account_id,region;
-- name: PutAuthority :exec
INSERT INTO signer_authorities(partition,account_id,region,certificate,private_key) VALUES(?,?,?,?,?);
-- name: GetProfile :one
SELECT * FROM signer_profiles WHERE partition=? AND account_id=? AND region=? AND name=? AND version=?;
-- name: GetCurrentProfile :one
SELECT * FROM signer_profiles WHERE partition=? AND account_id=? AND region=? AND name=? AND is_current=1;
-- name: ListProfiles :many
SELECT * FROM signer_profiles WHERE partition=? AND account_id=? AND region=? ORDER BY version_arn;
-- name: PutProfile :exec
INSERT INTO signer_profiles(partition,account_id,region,name,arn,version,version_arn,status,is_current,validity_value,validity_type,created,revoked_at,effective_time,revocation_reason,revoked_by,certificate,private_key)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name,version) DO UPDATE SET status=excluded.status,is_current=excluded.is_current,revoked_at=excluded.revoked_at,effective_time=excluded.effective_time,revocation_reason=excluded.revocation_reason,revoked_by=excluded.revoked_by;
-- name: ListProfileTags :many
SELECT tag_key,tag_value FROM signer_profile_tags WHERE version_arn=? ORDER BY tag_key;
-- name: DeleteProfileTags :exec
DELETE FROM signer_profile_tags WHERE version_arn=?;
-- name: PutProfileTag :exec
INSERT INTO signer_profile_tags(version_arn,tag_key,tag_value) VALUES(?,?,?);
-- name: GetJob :one
SELECT * FROM signer_jobs WHERE partition=? AND account_id=? AND region=? AND id=?;
-- name: ListJobs :many
SELECT * FROM signer_jobs WHERE partition=? AND account_id=? AND region=? ORDER BY id;
-- name: PutJob :exec
INSERT INTO signer_jobs(partition,account_id,region,id,arn,profile_name,profile_version,profile_version_arn,token,source_bucket,source_key,source_version,destination_bucket,destination_prefix,destination_key,status,status_reason,requested_by,created,completed,expires,revoked_at,revocation_reason,revoked_by)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,id) DO UPDATE SET status=excluded.status,status_reason=excluded.status_reason,completed=excluded.completed,revoked_at=excluded.revoked_at,revocation_reason=excluded.revocation_reason,revoked_by=excluded.revoked_by;
-- name: ListJobCertificates :many
SELECT certificate_hash FROM signer_job_certificates WHERE job_arn=? ORDER BY position;
-- name: DeleteJobCertificates :exec
DELETE FROM signer_job_certificates WHERE job_arn=?;
-- name: PutJobCertificate :exec
INSERT INTO signer_job_certificates(job_arn,position,certificate_hash) VALUES(?,?,?);
