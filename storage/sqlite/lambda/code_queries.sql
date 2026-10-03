-- name: GetCodeArchive :one
SELECT * FROM lambda_code_archives WHERE partition=? AND account=? AND region=? AND code_sha256=?;

-- name: PutCodeArchive :exec
INSERT INTO lambda_code_archives(partition,account,region,code_sha256,code,created_at,retain_until)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,code_sha256)
DO UPDATE SET retain_until=MAX(lambda_code_archives.retain_until,excluded.retain_until);

-- name: RetainCodeArchive :execrows
UPDATE lambda_code_archives
SET retain_until=CASE WHEN retain_until < sqlc.arg(retain_until) THEN sqlc.arg(retain_until) ELSE retain_until END
WHERE partition=sqlc.arg(partition) AND account=sqlc.arg(account) AND region=sqlc.arg(region) AND code_sha256=sqlc.arg(code_sha256);

-- name: NextCodeArchiveDeadline :one
SELECT retain_until FROM lambda_code_archives AS a
WHERE NOT EXISTS (SELECT 1 FROM lambda_functions AS f WHERE f.partition=a.partition AND f.account=a.account AND f.region=a.region AND f.code_sha256=a.code_sha256)
AND NOT EXISTS (SELECT 1 FROM lambda_layer_versions AS l WHERE l.partition=a.partition AND l.account=a.account AND l.region=a.region AND l.code_sha256=a.code_sha256)
AND NOT EXISTS (SELECT 1 FROM lambda_function_layers AS l WHERE l.layer_partition=a.partition AND l.layer_account=a.account AND l.layer_region=a.region AND l.code_sha256=a.code_sha256)
ORDER BY retain_until LIMIT 1;

-- name: DeleteExpiredCodeArchives :execrows
DELETE FROM lambda_code_archives AS a WHERE retain_until < sqlc.arg(now)
AND NOT EXISTS (SELECT 1 FROM lambda_functions AS f WHERE f.partition=a.partition AND f.account=a.account AND f.region=a.region AND f.code_sha256=a.code_sha256)
AND NOT EXISTS (SELECT 1 FROM lambda_layer_versions AS l WHERE l.partition=a.partition AND l.account=a.account AND l.region=a.region AND l.code_sha256=a.code_sha256)
AND NOT EXISTS (SELECT 1 FROM lambda_function_layers AS l WHERE l.layer_partition=a.partition AND l.layer_account=a.account AND l.layer_region=a.region AND l.code_sha256=a.code_sha256);

-- name: GetCodeSigningKey :one
SELECT * FROM lambda_code_signing_keys WHERE partition=? AND account=? AND region=?;

-- name: PutCodeSigningKey :exec
INSERT INTO lambda_code_signing_keys(partition,account,region,access_key_id,secret_access_key)
VALUES(?,?,?,?,?) ON CONFLICT(partition,account,region) DO NOTHING;
