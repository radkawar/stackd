-- name: NextMetricPublication :one
SELECT partition,account_id,region,table_name,minute FROM dynamodb_metric_samples
ORDER BY minute,partition,account_id,region,table_name LIMIT 1;

-- name: GetMetricSamples :many
SELECT index_name,operation,operation_type,verb,metric_name,value,sample_count FROM dynamodb_metric_samples
WHERE partition=? AND account_id=? AND region=? AND table_name=? AND minute=?
ORDER BY index_name,operation,operation_type,verb,metric_name,value;

-- name: AddMetricSample :exec
INSERT INTO dynamodb_metric_samples(partition,account_id,region,table_name,minute,index_name,operation,operation_type,verb,metric_name,value,sample_count)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,table_name,minute,index_name,operation,operation_type,verb,metric_name,value) DO UPDATE SET
sample_count=dynamodb_metric_samples.sample_count+excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM dynamodb_metric_samples WHERE partition=? AND account_id=? AND region=? AND table_name=? AND minute=?;

-- name: NextMetricTable :one
SELECT * FROM dynamodb_tables WHERE table_status IN ('ACTIVE','UPDATING')
ORDER BY metrics_next_at,partition,account_id,region,name LIMIT 1;
