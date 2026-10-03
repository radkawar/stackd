-- name: GetMQMapping :one
SELECT * FROM lambda_mq_mappings WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutMQMapping :exec
INSERT INTO lambda_mq_mappings(partition,account,region,uuid,queue_name,virtual_host,secret_arn,broker_id,engine,batching_window_ns,virtual_host_set)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET queue_name=excluded.queue_name,virtual_host=excluded.virtual_host,secret_arn=excluded.secret_arn,broker_id=excluded.broker_id,engine=excluded.engine,batching_window_ns=excluded.batching_window_ns,virtual_host_set=excluded.virtual_host_set;
