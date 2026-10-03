-- name: NextMetricPublication :one
SELECT partition,account,region,queue_name,minute FROM sqs_metric_samples
ORDER BY minute,partition,account,region,queue_name LIMIT 1;

-- name: GetMetricSamples :many
SELECT metric_name,value,sample_count FROM sqs_metric_samples
WHERE partition=? AND account=? AND region=? AND queue_name=? AND minute=?
ORDER BY metric_name,value;

-- name: AddMetricSample :exec
INSERT INTO sqs_metric_samples(partition,account,region,queue_name,minute,metric_name,value,sample_count)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,queue_name,minute,metric_name,value) DO UPDATE SET
sample_count=sqs_metric_samples.sample_count+excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM sqs_metric_samples WHERE partition=? AND account=? AND region=? AND queue_name=? AND minute=?;
