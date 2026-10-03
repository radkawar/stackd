-- name: GetInstanceReservation :one
SELECT * FROM ec2_reservations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: InstanceReservationsByToken :many
SELECT * FROM ec2_reservations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND client_token = sqlc.arg(client_token) AND client_token != '' ORDER BY resource_id;

-- name: PutInstanceReservation :exec
INSERT INTO ec2_reservations (partition, account_id, region, resource_id, client_token, token_zone, requester_id, launch_principal_arn, launch_principal_id, image_id, instance_type, min_count, max_count, key_name, subnet_id, private_ip_address, user_data, disable_api_stop, disable_api_termination, ebs_optimized, shutdown_behavior, cpu_options, credit_specification, iam_instance_profile, metadata_options, monitoring, placement, instances_present, mappings_present, networks_present, groups_present, tags_present, elastic_gpu_specification_present, elastic_inference_accelerators_present, ipv6_addresses_present, license_specifications_present, secondary_interfaces_present, security_groups_present, launch_template)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(client_token), sqlc.arg(token_zone), sqlc.arg(requester_id), sqlc.arg(launch_principal_arn), sqlc.arg(launch_principal_id), sqlc.arg(image_id), sqlc.arg(instance_type), sqlc.arg(min_count), sqlc.arg(max_count), sqlc.arg(key_name), sqlc.arg(subnet_id), sqlc.arg(private_ip_address), sqlc.arg(user_data), sqlc.arg(disable_api_stop), sqlc.arg(disable_api_termination), sqlc.arg(ebs_optimized), sqlc.arg(shutdown_behavior), sqlc.arg(cpu_options), sqlc.arg(credit_specification), sqlc.arg(iam_instance_profile), sqlc.arg(metadata_options), sqlc.arg(monitoring), sqlc.arg(placement), sqlc.arg(instances_present), sqlc.arg(mappings_present), sqlc.arg(networks_present), sqlc.arg(groups_present), sqlc.arg(tags_present), sqlc.arg(elastic_gpu_specification_present), sqlc.arg(elastic_inference_accelerators_present), sqlc.arg(ipv6_addresses_present), sqlc.arg(license_specifications_present), sqlc.arg(secondary_interfaces_present), sqlc.arg(security_groups_present), sqlc.arg(launch_template))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET client_token = excluded.client_token, token_zone = excluded.token_zone, requester_id = excluded.requester_id, launch_principal_arn = excluded.launch_principal_arn, launch_principal_id = excluded.launch_principal_id, image_id = excluded.image_id, instance_type = excluded.instance_type, min_count = excluded.min_count, max_count = excluded.max_count, key_name = excluded.key_name, subnet_id = excluded.subnet_id, private_ip_address = excluded.private_ip_address, user_data = excluded.user_data, disable_api_stop = excluded.disable_api_stop, disable_api_termination = excluded.disable_api_termination, ebs_optimized = excluded.ebs_optimized, shutdown_behavior = excluded.shutdown_behavior, cpu_options = excluded.cpu_options, credit_specification = excluded.credit_specification, iam_instance_profile = excluded.iam_instance_profile, metadata_options = excluded.metadata_options, monitoring = excluded.monitoring, placement = excluded.placement, instances_present = excluded.instances_present, mappings_present = excluded.mappings_present, networks_present = excluded.networks_present, groups_present = excluded.groups_present, tags_present = excluded.tags_present, elastic_gpu_specification_present = excluded.elastic_gpu_specification_present, elastic_inference_accelerators_present = excluded.elastic_inference_accelerators_present, ipv6_addresses_present = excluded.ipv6_addresses_present, license_specifications_present = excluded.license_specifications_present, secondary_interfaces_present = excluded.secondary_interfaces_present, security_groups_present = excluded.security_groups_present, launch_template = excluded.launch_template;

-- name: ListReservationInstances :many
SELECT * FROM ec2_reservation_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteReservationInstances :exec
DELETE FROM ec2_reservation_instances WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutReservationInstance :exec
INSERT INTO ec2_reservation_instances (partition, account_id, region, resource_id, position, instance_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(instance_id));

-- name: ListReservationMappings :many
SELECT * FROM ec2_reservation_mappings WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteReservationMappings :exec
DELETE FROM ec2_reservation_mappings WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutReservationMapping :exec
INSERT INTO ec2_reservation_mappings (partition, account_id, region, resource_id, position, device_name, no_device, virtual_name, ebs) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(device_name), sqlc.arg(no_device), sqlc.arg(virtual_name), sqlc.arg(ebs));

-- name: ListReservationNetworks :many
SELECT * FROM ec2_reservation_networks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteReservationNetworks :exec
DELETE FROM ec2_reservation_networks WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutReservationNetwork :exec
INSERT INTO ec2_reservation_networks (partition, account_id, region, resource_id, position, associate_carrier_ip_address, associate_public_ip_address, delete_on_termination, description, device_index, interface_type, network_card_index, network_interface_id, private_ip_address, subnet_id, groups_present, ipv4_prefixes_present, ipv6_addresses_present, ipv6_prefixes_present, private_ip_addresses_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(associate_carrier_ip_address), sqlc.arg(associate_public_ip_address), sqlc.arg(delete_on_termination), sqlc.arg(description), sqlc.arg(device_index), sqlc.arg(interface_type), sqlc.arg(network_card_index), sqlc.arg(network_interface_id), sqlc.arg(private_ip_address), sqlc.arg(subnet_id), sqlc.arg(groups_present), sqlc.arg(ipv4_prefixes_present), sqlc.arg(ipv6_addresses_present), sqlc.arg(ipv6_prefixes_present), sqlc.arg(private_ip_addresses_present));

-- name: ListReservationNetworkGroups :many
SELECT * FROM ec2_reservation_network_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) AND network_position = sqlc.arg(network_position) ORDER BY position;

-- name: PutReservationNetworkGroup :exec
INSERT INTO ec2_reservation_network_groups (partition, account_id, region, resource_id, network_position, position, group_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(network_position), sqlc.arg(position), sqlc.arg(group_id));

-- name: ListReservationGroups :many
SELECT * FROM ec2_reservation_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteReservationGroups :exec
DELETE FROM ec2_reservation_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutReservationGroup :exec
INSERT INTO ec2_reservation_groups (partition, account_id, region, resource_id, position, group_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(group_id));

-- name: ListReservationTagSpecifications :many
SELECT * FROM ec2_reservation_tag_specifications WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: DeleteReservationTagSpecifications :exec
DELETE FROM ec2_reservation_tag_specifications WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: PutReservationTagSpecification :exec
INSERT INTO ec2_reservation_tag_specifications (partition, account_id, region, resource_id, position, resource_type, tags_present) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(resource_type), sqlc.arg(tags_present));

-- name: ListReservationTags :many
SELECT * FROM ec2_reservation_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) AND specification_position = sqlc.arg(specification_position) ORDER BY position;

-- name: PutReservationTag :exec
INSERT INTO ec2_reservation_tags (partition, account_id, region, resource_id, specification_position, position, key, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(specification_position), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));
