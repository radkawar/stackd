-- name: GetKafkaMapping :one
SELECT * FROM lambda_kafka_mappings WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutKafkaMapping :exec
INSERT INTO lambda_kafka_mappings(partition,account,region,uuid,topic,consumer_group_id,starting_position,starting_position_timestamp,batching_window_ns,authentication,secret_arn,cluster_id,topic_id,root_ca_secret_arn,network_role_arn)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET topic=excluded.topic,consumer_group_id=excluded.consumer_group_id,starting_position=excluded.starting_position,starting_position_timestamp=excluded.starting_position_timestamp,batching_window_ns=excluded.batching_window_ns,authentication=excluded.authentication,secret_arn=excluded.secret_arn,cluster_id=excluded.cluster_id,topic_id=excluded.topic_id,root_ca_secret_arn=excluded.root_ca_secret_arn,network_role_arn=excluded.network_role_arn;

-- name: ListKafkaBootstrapServers :many
SELECT endpoint FROM lambda_kafka_bootstrap_servers WHERE partition=? AND account=? AND region=? AND uuid=? ORDER BY position;

-- name: DeleteKafkaBootstrapServers :exec
DELETE FROM lambda_kafka_bootstrap_servers WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutKafkaBootstrapServer :exec
INSERT INTO lambda_kafka_bootstrap_servers(partition,account,region,uuid,position,endpoint) VALUES(?,?,?,?,?,?);

-- name: ListKafkaNetworkComponents :many
SELECT kind,resource_id FROM lambda_kafka_network_components WHERE partition=? AND account=? AND region=? AND uuid=? ORDER BY kind,resource_id;

-- name: DeleteKafkaNetworkComponents :exec
DELETE FROM lambda_kafka_network_components WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutKafkaNetworkComponent :exec
INSERT INTO lambda_kafka_network_components(partition,account,region,uuid,kind,resource_id) VALUES(?,?,?,?,?,?);
