-- name: ListInstancePerformanceGroups :many
SELECT * FROM ec2_instance_performance_groups
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id)
  AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id)
ORDER BY group_name;

-- name: DeleteInstancePerformanceGroups :exec
DELETE FROM ec2_instance_performance_groups
WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id)
  AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutInstancePerformanceGroup :exec
INSERT INTO ec2_instance_performance_groups (
 partition, account_id, region, resource_id, group_name,
 cpu_count, cpu_sum, cpu_min, cpu_max, network_in, network_out, network_observed
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(group_name),
 sqlc.arg(cpu_count), sqlc.arg(cpu_sum), sqlc.arg(cpu_min), sqlc.arg(cpu_max),
 sqlc.arg(network_in), sqlc.arg(network_out), sqlc.arg(network_observed)
);
