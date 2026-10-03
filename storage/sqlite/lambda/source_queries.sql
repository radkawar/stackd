-- name: GetFunctionS3Source :one
SELECT reference_bucket,reference_key,reference_version_id,code_source_check_at FROM lambda_function_s3_sources
WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionS3Source :exec
INSERT INTO lambda_function_s3_sources(partition,account,region,function_name,pending,version,reference_bucket,reference_key,reference_version_id,code_source_check_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET
reference_bucket=excluded.reference_bucket,reference_key=excluded.reference_key,reference_version_id=excluded.reference_version_id,code_source_check_at=excluded.code_source_check_at;
-- name: DeleteFunctionS3Source :exec
DELETE FROM lambda_function_s3_sources WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: NextCodeSourceCheck :one
SELECT s.partition,s.account,s.region,s.function_name,s.version,s.code_source_check_at
FROM lambda_function_s3_sources s JOIN lambda_functions f
ON f.partition=s.partition AND f.account=s.account AND f.region=s.region AND f.name=s.function_name AND f.pending=s.pending AND f.version=s.version
WHERE s.pending=false AND f.state='Active' AND f.update_status!='InProgress'
ORDER BY s.code_source_check_at,
'arn:' || s.partition || ':lambda:' || s.region || ':' || s.account || ':function:' || s.function_name || CASE WHEN s.version=0 THEN '' ELSE ':' || CAST(s.version AS TEXT) END
LIMIT 1;
-- name: SetCodeSourceState :exec
UPDATE lambda_functions SET state=?,state_reason=?,state_reason_code=?,revision=?
WHERE partition=? AND account=? AND region=? AND name=? AND pending=false AND version=?;
-- name: SetCodeSourceCheckAt :exec
UPDATE lambda_function_s3_sources SET code_source_check_at=?
WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=false AND version=?;
