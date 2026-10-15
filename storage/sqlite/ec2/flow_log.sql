-- name: GetFlowLog :one
SELECT * FROM ec2_flow_logs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListFlowLogs :many
SELECT * FROM ec2_flow_logs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: ListInternalFlowLogs :many
SELECT * FROM ec2_flow_logs ORDER BY partition, account_id, region, resource_id;

-- name: PutFlowLog :exec
INSERT INTO ec2_flow_logs (partition, account_id, region, resource_id, incarnation, selector_resource_id, resource_type, traffic_type, destination_type, destination, log_group_name, permission_arn, log_format, format_version, aggregation_seconds, hive_partitions, hour_partitions, tags_present, created_at, status, delivery_status, delivery_error, capture_error, version)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(incarnation), sqlc.arg(selector_resource_id), sqlc.arg(resource_type), sqlc.arg(traffic_type), sqlc.arg(destination_type), sqlc.arg(destination), sqlc.arg(log_group_name), sqlc.arg(permission_arn), sqlc.arg(log_format), sqlc.arg(format_version), sqlc.arg(aggregation_seconds), sqlc.arg(hive_partitions), sqlc.arg(hour_partitions), sqlc.arg(tags_present), sqlc.arg(created_at), sqlc.arg(status), sqlc.arg(delivery_status), sqlc.arg(delivery_error), sqlc.arg(capture_error), sqlc.arg(version))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET incarnation = excluded.incarnation, selector_resource_id = excluded.selector_resource_id, resource_type = excluded.resource_type, traffic_type = excluded.traffic_type, destination_type = excluded.destination_type, destination = excluded.destination, log_group_name = excluded.log_group_name, permission_arn = excluded.permission_arn, log_format = excluded.log_format, format_version = excluded.format_version, aggregation_seconds = excluded.aggregation_seconds, hive_partitions = excluded.hive_partitions, hour_partitions = excluded.hour_partitions, tags_present = excluded.tags_present, created_at = excluded.created_at, status = excluded.status, delivery_status = excluded.delivery_status, delivery_error = excluded.delivery_error, capture_error = excluded.capture_error, version = excluded.version;

-- name: DeleteFlowLog :execrows
DELETE FROM ec2_flow_logs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListFlowLogTags :many
SELECT * FROM ec2_flow_log_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteFlowLogTags :exec
DELETE FROM ec2_flow_log_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutFlowLogTag :exec
INSERT INTO ec2_flow_log_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: ListFlowLogTokenResults :many
SELECT * FROM ec2_flow_log_token_results WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: DeleteFlowLogTokenResults :exec
DELETE FROM ec2_flow_log_token_results WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutFlowLogTokenResult :exec
INSERT INTO ec2_flow_log_token_results (partition, account_id, region, token, position, selector_resource_id, flow_log_id, error_code, error_message)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(selector_resource_id), sqlc.arg(flow_log_id), sqlc.arg(error_code), sqlc.arg(error_message));

-- name: ListFlowLogDeliveryLines :many
SELECT * FROM ec2_flow_log_delivery_lines WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutFlowLogDeliveryLine :exec
INSERT INTO ec2_flow_log_delivery_lines (partition, account_id, region, resource_id, position, start, interface_id, message)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(start), sqlc.arg(interface_id), sqlc.arg(message));

-- name: GetFlowLogToken :one
SELECT * FROM ec2_flow_log_tokens WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutFlowLogToken :exec
INSERT INTO ec2_flow_log_tokens (partition, account_id, region, token, fingerprint, results_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(fingerprint), sqlc.arg(results_present))
ON CONFLICT (partition, account_id, region, token) DO UPDATE SET fingerprint = excluded.fingerprint, results_present = excluded.results_present;

-- name: GetFlowLogCaptureState :one
SELECT * FROM ec2_flow_log_capture WHERE singleton = 1;

-- name: PutFlowLogCaptureState :exec
INSERT INTO ec2_flow_log_capture (singleton, cursor, due, version)
VALUES (1, sqlc.arg(cursor), sqlc.arg(due), sqlc.arg(version))
ON CONFLICT (singleton) DO UPDATE SET cursor = excluded.cursor, due = excluded.due, version = excluded.version;

-- name: ListFlowLogAggregates :many
SELECT * FROM ec2_flow_log_aggregates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND flow_log_id = sqlc.arg(flow_log_id) ORDER BY aggregate_id;

-- name: PutFlowLogAggregate :exec
INSERT INTO ec2_flow_log_aggregates (partition, account_id, region, flow_log_id, aggregate_id, incarnation, interface_partition, interface_account_id, interface_region, interface_id, interface_incarnation, network_id, address, vpc_id, subnet_id, instance_id, availability_zone_id, source_address, destination_address, source_port, destination_port, protocol, action, direction, packets, bytes, start, end, due, tcp_flags, lost)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(flow_log_id), sqlc.arg(aggregate_id), sqlc.arg(incarnation), sqlc.arg(interface_partition), sqlc.arg(interface_account_id), sqlc.arg(interface_region), sqlc.arg(interface_id), sqlc.arg(interface_incarnation), sqlc.arg(network_id), sqlc.arg(address), sqlc.arg(vpc_id), sqlc.arg(subnet_id), sqlc.arg(instance_id), sqlc.arg(availability_zone_id), sqlc.arg(source_address), sqlc.arg(destination_address), sqlc.arg(source_port), sqlc.arg(destination_port), sqlc.arg(protocol), sqlc.arg(action), sqlc.arg(direction), sqlc.arg(packets), sqlc.arg(bytes), sqlc.arg(start), sqlc.arg(end), sqlc.arg(due), sqlc.arg(tcp_flags), sqlc.arg(lost))
ON CONFLICT (partition, account_id, region, flow_log_id, aggregate_id) DO UPDATE SET incarnation = excluded.incarnation, interface_partition = excluded.interface_partition, interface_account_id = excluded.interface_account_id, interface_region = excluded.interface_region, interface_id = excluded.interface_id, interface_incarnation = excluded.interface_incarnation, network_id = excluded.network_id, address = excluded.address, vpc_id = excluded.vpc_id, subnet_id = excluded.subnet_id, instance_id = excluded.instance_id, availability_zone_id = excluded.availability_zone_id, source_address = excluded.source_address, destination_address = excluded.destination_address, source_port = excluded.source_port, destination_port = excluded.destination_port, protocol = excluded.protocol, action = excluded.action, direction = excluded.direction, packets = excluded.packets, bytes = excluded.bytes, start = excluded.start, end = excluded.end, due = excluded.due, tcp_flags = excluded.tcp_flags, lost = excluded.lost;

-- name: DeleteFlowLogAggregate :execrows
DELETE FROM ec2_flow_log_aggregates WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND flow_log_id = sqlc.arg(flow_log_id) AND aggregate_id = sqlc.arg(aggregate_id);

-- name: GetFlowLogDelivery :one
SELECT * FROM ec2_flow_log_deliveries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListFlowLogDeliveries :many
SELECT * FROM ec2_flow_log_deliveries ORDER BY partition, account_id, region, resource_id;

-- name: PutFlowLogDelivery :exec
INSERT INTO ec2_flow_log_deliveries (partition, account_id, region, resource_id, flow_log_id, incarnation, destination_type, destination, log_group_name, permission_arn, hive_partitions, hour_partitions, header, lines_present, window_start, due, version)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(flow_log_id), sqlc.arg(incarnation), sqlc.arg(destination_type), sqlc.arg(destination), sqlc.arg(log_group_name), sqlc.arg(permission_arn), sqlc.arg(hive_partitions), sqlc.arg(hour_partitions), sqlc.arg(header), sqlc.arg(lines_present), sqlc.arg(window_start), sqlc.arg(due), sqlc.arg(version))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET due = excluded.due, version = excluded.version;

-- name: DeleteFlowLogDelivery :execrows
DELETE FROM ec2_flow_log_deliveries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);
