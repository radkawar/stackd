-- name: GetFunctionConcurrency :one
SELECT reserved_concurrency FROM lambda_function_concurrency WHERE partition=? AND account=? AND region=? AND function_name=?;
-- name: PutFunctionConcurrency :exec
INSERT INTO lambda_function_concurrency(partition,account,region,function_name,reserved_concurrency) VALUES(?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name) DO UPDATE SET reserved_concurrency=excluded.reserved_concurrency;
-- name: DeleteFunctionConcurrency :exec
DELETE FROM lambda_function_concurrency WHERE partition=? AND account=? AND region=? AND function_name=?;
-- name: GetAccountUsage :one
SELECT CAST(COALESCE(SUM(CASE WHEN f.version=0 THEN 1 ELSE 0 END),0) AS INTEGER) AS function_count,
    CAST(COALESCE(SUM(CASE WHEN s.function_name IS NULL THEN f.code_size ELSE 0 END),0)
        + (SELECT COALESCE(SUM(l.code_size),0) FROM lambda_layer_versions AS l WHERE l.partition=sqlc.arg(partition) AND l.account=sqlc.arg(account) AND l.region=sqlc.arg(region) AND l.has_reference=false)
        AS INTEGER) AS total_code_size,
    CAST(COALESCE(SUM(c.reserved_concurrency),0) AS INTEGER) AS reserved_concurrency
FROM lambda_functions AS f
LEFT JOIN lambda_function_concurrency AS c ON c.partition=f.partition AND c.account=f.account AND c.region=f.region AND c.function_name=f.name AND f.version=0
LEFT JOIN lambda_function_s3_sources AS s ON s.partition=f.partition AND s.account=f.account AND s.region=f.region AND s.function_name=f.name AND s.pending=f.pending AND s.version=f.version
WHERE f.partition=sqlc.arg(partition) AND f.account=sqlc.arg(account) AND f.region=sqlc.arg(region) AND f.pending=false;
