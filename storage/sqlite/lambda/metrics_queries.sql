-- name: NextMetricPublication :one
SELECT partition,account,region,function_name,resource,executed_version,event_source_mapping_uuid,minute FROM lambda_metric_samples
ORDER BY minute,partition,account,region,function_name,resource,executed_version,event_source_mapping_uuid LIMIT 1;

-- name: GetMetricSamples :many
SELECT metric_name,value,sample_count FROM lambda_metric_samples
WHERE partition=? AND account=? AND region=? AND function_name=? AND resource=? AND executed_version=? AND event_source_mapping_uuid=? AND minute=?
ORDER BY metric_name,value;

-- name: AddMetricSample :exec
INSERT INTO lambda_metric_samples(partition,account,region,function_name,resource,executed_version,event_source_mapping_uuid,minute,metric_name,value,sample_count)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,resource,executed_version,event_source_mapping_uuid,minute,metric_name,value) DO UPDATE SET
sample_count=lambda_metric_samples.sample_count+excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM lambda_metric_samples WHERE partition=? AND account=? AND region=? AND function_name=? AND resource=? AND executed_version=? AND event_source_mapping_uuid=? AND minute=?;
