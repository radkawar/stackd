-- name: NextMetricPublication :one
SELECT partition,account,region,minute FROM eventbridge_metric_samples
ORDER BY minute,partition,account,region LIMIT 1;

-- name: GetMetricSamples :many
SELECT metric_name,event_bus_name,rule_name,source,value,sample_count FROM eventbridge_metric_samples
WHERE partition=? AND account=? AND region=? AND minute=?
ORDER BY metric_name,event_bus_name,rule_name,source,value;

-- name: AddMetricSample :exec
INSERT INTO eventbridge_metric_samples(partition,account,region,minute,metric_name,event_bus_name,rule_name,source,value,sample_count)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,minute,metric_name,event_bus_name,rule_name,source,value) DO UPDATE SET
sample_count=eventbridge_metric_samples.sample_count+excluded.sample_count;

-- name: DeleteMetricPublication :exec
DELETE FROM eventbridge_metric_samples WHERE partition=? AND account=? AND region=? AND minute=?;
