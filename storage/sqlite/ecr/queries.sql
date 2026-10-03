-- name: GetRepository :one
SELECT * FROM ecr_repositories WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: PutRepository :exec
INSERT INTO ecr_repositories (partition,account_id,region,name,arn,created,mutability,exclusions,tags,policy,policy_principals,encryption_type,kms_key_id,data_key,grants,grant_tokens,scan_on_push,lifecycle_policy,lifecycle_due,lifecycle_evaluated,preview_policy,preview_status,preview_results,preview_expires) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,name) DO UPDATE SET arn=excluded.arn,created=excluded.created,mutability=excluded.mutability,exclusions=excluded.exclusions,tags=excluded.tags,policy=excluded.policy,policy_principals=excluded.policy_principals,encryption_type=excluded.encryption_type,kms_key_id=excluded.kms_key_id,data_key=excluded.data_key,grants=excluded.grants,grant_tokens=excluded.grant_tokens,scan_on_push=excluded.scan_on_push,lifecycle_policy=excluded.lifecycle_policy,lifecycle_due=excluded.lifecycle_due,lifecycle_evaluated=excluded.lifecycle_evaluated,preview_policy=excluded.preview_policy,preview_status=excluded.preview_status,preview_results=excluded.preview_results,preview_expires=excluded.preview_expires;

-- name: DeleteRepository :exec
DELETE FROM ecr_repositories WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;

-- name: GetRegistry :one
SELECT * FROM ecr_registries WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutRegistry :exec
INSERT INTO ecr_registries (partition,account_id,region,policy,policy_principals,scanning,replication) VALUES (?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region) DO UPDATE SET policy=excluded.policy,policy_principals=excluded.policy_principals,scanning=excluded.scanning,replication=excluded.replication;

-- name: GetImage :one
SELECT * FROM ecr_images WHERE partition = ? AND account_id = ? AND region = ? AND repository = ? AND digest = ?;

-- name: PutImage :exec
INSERT INTO ecr_images (partition,account_id,region,repository,digest,media_type,artifact_media_type,payload,size,pushed,last_pull,tags,refs,layers,scan_id,scan_status,scan_description,scan_started,scan_completed,vulnerability_updated,findings) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,repository,digest) DO UPDATE SET media_type=excluded.media_type,artifact_media_type=excluded.artifact_media_type,payload=excluded.payload,size=excluded.size,pushed=excluded.pushed,last_pull=excluded.last_pull,tags=excluded.tags,refs=excluded.refs,layers=excluded.layers,scan_id=excluded.scan_id,scan_status=excluded.scan_status,scan_description=excluded.scan_description,scan_started=excluded.scan_started,scan_completed=excluded.scan_completed,vulnerability_updated=excluded.vulnerability_updated,findings=excluded.findings;

-- name: DeleteImage :exec
DELETE FROM ecr_images WHERE partition = ? AND account_id = ? AND region = ? AND repository = ? AND digest = ?;

-- name: GetBlob :one
SELECT * FROM ecr_blobs WHERE partition = ? AND account_id = ? AND region = ? AND repository = ? AND digest = ?;

-- name: PutBlob :exec
INSERT INTO ecr_blobs (partition,account_id,region,repository,digest,payload,size) VALUES (?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,repository,digest) DO UPDATE SET payload=excluded.payload,size=excluded.size;

-- name: GetUpload :one
SELECT * FROM ecr_uploads WHERE partition = ? AND account_id = ? AND region = ? AND repository = ? AND id = ?;

-- name: PutUpload :exec
INSERT INTO ecr_uploads (partition,account_id,region,repository,id,payload,size,expires) VALUES (?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,repository,id) DO UPDATE SET payload=excluded.payload,size=excluded.size,expires=excluded.expires;

-- name: DeleteUpload :exec
DELETE FROM ecr_uploads WHERE partition = ? AND account_id = ? AND region = ? AND repository = ? AND id = ?;

-- name: GetToken :one
SELECT * FROM ecr_tokens WHERE hash = ?;

-- name: PutToken :exec
INSERT INTO ecr_tokens (hash,partition,region,identity,expires,download_partition,download_account,download_region,download_repository,download_digest) VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (hash) DO UPDATE SET partition=excluded.partition,region=excluded.region,identity=excluded.identity,expires=excluded.expires,download_partition=excluded.download_partition,download_account=excluded.download_account,download_region=excluded.download_region,download_repository=excluded.download_repository,download_digest=excluded.download_digest;

-- name: ListRepositories :many
SELECT * FROM ecr_repositories WHERE partition=? AND account_id=? AND region=? ORDER BY name;

-- name: AllRepositories :many
SELECT * FROM ecr_repositories ORDER BY arn;

-- name: ListImages :many
SELECT * FROM ecr_images WHERE partition=? AND account_id=? AND region=? AND repository=? ORDER BY digest;

-- name: DeleteExpiredTokens :exec
DELETE FROM ecr_tokens WHERE expires <= ?;

-- name: AllRegistries :many
SELECT * FROM ecr_registries ORDER BY partition,account_id,region;

-- name: ListReplications :many
SELECT * FROM ecr_replications ORDER BY due,partition,account_id,region,repository,digest,destination_partition,destination_account,destination_region;

-- name: PutReplication :exec
INSERT INTO ecr_replications (partition,account_id,region,repository,digest,destination_partition,destination_account,destination_region,tags,due,status,error,origin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (partition,account_id,region,repository,digest,destination_partition,destination_account,destination_region) DO UPDATE SET tags=excluded.tags,due=excluded.due,status=excluded.status,error=excluded.error,origin=excluded.origin;
