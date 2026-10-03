-- name: PutLTVersion :exec
INSERT INTO ec2_lt_version_record (partition, account_id, region, resource_id, version, created_at, created_by, description, block_device_mappings_present, capacity_reservation_specification, cpu_options, credit_specification, disable_api_stop, disable_api_termination, ebs_optimized, elastic_gpu_specifications_present, elastic_inference_accelerators_present, enclave_options, hibernation_options, iam_instance_profile, image_id, instance_initiated_shutdown_behavior, instance_market_options, instance_requirements, instance_type, kernel_id, key_name, license_specifications_present, maintenance_options, metadata_options, monitoring, network_interfaces_present, network_performance_options, operator, placement, private_dns_name_options, ram_disk_id, secondary_interfaces_present, security_group_ids_present, security_groups_present, tag_specifications_present, user_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version) DO UPDATE SET created_at=excluded.created_at, created_by=excluded.created_by, description=excluded.description, block_device_mappings_present=excluded.block_device_mappings_present, capacity_reservation_specification=excluded.capacity_reservation_specification, cpu_options=excluded.cpu_options, credit_specification=excluded.credit_specification, disable_api_stop=excluded.disable_api_stop, disable_api_termination=excluded.disable_api_termination, ebs_optimized=excluded.ebs_optimized, elastic_gpu_specifications_present=excluded.elastic_gpu_specifications_present, elastic_inference_accelerators_present=excluded.elastic_inference_accelerators_present, enclave_options=excluded.enclave_options, hibernation_options=excluded.hibernation_options, iam_instance_profile=excluded.iam_instance_profile, image_id=excluded.image_id, instance_initiated_shutdown_behavior=excluded.instance_initiated_shutdown_behavior, instance_market_options=excluded.instance_market_options, instance_requirements=excluded.instance_requirements, instance_type=excluded.instance_type, kernel_id=excluded.kernel_id, key_name=excluded.key_name, license_specifications_present=excluded.license_specifications_present, maintenance_options=excluded.maintenance_options, metadata_options=excluded.metadata_options, monitoring=excluded.monitoring, network_interfaces_present=excluded.network_interfaces_present, network_performance_options=excluded.network_performance_options, operator=excluded.operator, placement=excluded.placement, private_dns_name_options=excluded.private_dns_name_options, ram_disk_id=excluded.ram_disk_id, secondary_interfaces_present=excluded.secondary_interfaces_present, security_group_ids_present=excluded.security_group_ids_present, security_groups_present=excluded.security_groups_present, tag_specifications_present=excluded.tag_specifications_present, user_data=excluded.user_data;

-- name: GetLTVersion :one
SELECT * FROM ec2_lt_version_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: ListLTVersion :many
SELECT * FROM ec2_lt_version_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY version DESC;

-- name: DeleteLTVersion :execrows
DELETE FROM ec2_lt_version_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionBlockDeviceMappings :exec
INSERT INTO ec2_lt_version_block_device_mappings_record (partition, account_id, region, resource_id, version, version_position, device_name, ebs, no_device, virtual_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET device_name=excluded.device_name, ebs=excluded.ebs, no_device=excluded.no_device, virtual_name=excluded.virtual_name;

-- name: ListLTVersionBlockDeviceMappings :many
SELECT * FROM ec2_lt_version_block_device_mappings_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionBlockDeviceMappings :exec
DELETE FROM ec2_lt_version_block_device_mappings_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionElasticGpuSpecifications :exec
INSERT INTO ec2_lt_version_elastic_gpu_specifications_record (partition, account_id, region, resource_id, version, version_position, type) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET type=excluded.type;

-- name: ListLTVersionElasticGpuSpecifications :many
SELECT * FROM ec2_lt_version_elastic_gpu_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionElasticGpuSpecifications :exec
DELETE FROM ec2_lt_version_elastic_gpu_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionElasticInferenceAccelerators :exec
INSERT INTO ec2_lt_version_elastic_inference_accelerators_record (partition, account_id, region, resource_id, version, version_position, count, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET count=excluded.count, type=excluded.type;

-- name: ListLTVersionElasticInferenceAccelerators :many
SELECT * FROM ec2_lt_version_elastic_inference_accelerators_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionElasticInferenceAccelerators :exec
DELETE FROM ec2_lt_version_elastic_inference_accelerators_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionLicenseSpecifications :exec
INSERT INTO ec2_lt_version_license_specifications_record (partition, account_id, region, resource_id, version, version_position, license_configuration_arn) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET license_configuration_arn=excluded.license_configuration_arn;

-- name: ListLTVersionLicenseSpecifications :many
SELECT * FROM ec2_lt_version_license_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionLicenseSpecifications :exec
DELETE FROM ec2_lt_version_license_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionNetworkInterfaces :exec
INSERT INTO ec2_lt_version_network_interfaces_record (partition, account_id, region, resource_id, version, version_position, associate_carrier_ip_address, associate_public_ip_address, connection_tracking_specification, delete_on_termination, description, device_index, ena_queue_count, ena_srd_specification, groups_present, interface_type, ipv4_prefix_count, ipv4_prefixes_present, ipv6_address_count, ipv6_addresses_present, ipv6_prefix_count, ipv6_prefixes_present, network_card_index, network_interface_id, primary_ipv6, private_ip_address, private_ip_addresses_present, secondary_private_ip_address_count, subnet_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET associate_carrier_ip_address=excluded.associate_carrier_ip_address, associate_public_ip_address=excluded.associate_public_ip_address, connection_tracking_specification=excluded.connection_tracking_specification, delete_on_termination=excluded.delete_on_termination, description=excluded.description, device_index=excluded.device_index, ena_queue_count=excluded.ena_queue_count, ena_srd_specification=excluded.ena_srd_specification, groups_present=excluded.groups_present, interface_type=excluded.interface_type, ipv4_prefix_count=excluded.ipv4_prefix_count, ipv4_prefixes_present=excluded.ipv4_prefixes_present, ipv6_address_count=excluded.ipv6_address_count, ipv6_addresses_present=excluded.ipv6_addresses_present, ipv6_prefix_count=excluded.ipv6_prefix_count, ipv6_prefixes_present=excluded.ipv6_prefixes_present, network_card_index=excluded.network_card_index, network_interface_id=excluded.network_interface_id, primary_ipv6=excluded.primary_ipv6, private_ip_address=excluded.private_ip_address, private_ip_addresses_present=excluded.private_ip_addresses_present, secondary_private_ip_address_count=excluded.secondary_private_ip_address_count, subnet_id=excluded.subnet_id;

-- name: ListLTVersionNetworkInterfaces :many
SELECT * FROM ec2_lt_version_network_interfaces_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionNetworkInterfaces :exec
DELETE FROM ec2_lt_version_network_interfaces_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionNetworkInterfacesGroups :exec
INSERT INTO ec2_lt_version_network_interfaces_groups_record (partition, account_id, region, resource_id, version, version_position, version_network_interfaces_position, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position) DO UPDATE SET value=excluded.value;

-- name: ListLTVersionNetworkInterfacesGroups :many
SELECT * FROM ec2_lt_version_network_interfaces_groups_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_network_interfaces_position;

-- name: ClearLTVersionNetworkInterfacesGroups :exec
DELETE FROM ec2_lt_version_network_interfaces_groups_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionNetworkInterfacesIpv4Prefixes :exec
INSERT INTO ec2_lt_version_network_interfaces_ipv4_prefixes_record (partition, account_id, region, resource_id, version, version_position, version_network_interfaces_position, ipv4_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position) DO UPDATE SET ipv4_prefix=excluded.ipv4_prefix;

-- name: ListLTVersionNetworkInterfacesIpv4Prefixes :many
SELECT * FROM ec2_lt_version_network_interfaces_ipv4_prefixes_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_network_interfaces_position;

-- name: ClearLTVersionNetworkInterfacesIpv4Prefixes :exec
DELETE FROM ec2_lt_version_network_interfaces_ipv4_prefixes_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionNetworkInterfacesIpv6Addresses :exec
INSERT INTO ec2_lt_version_network_interfaces_ipv6_addresses_record (partition, account_id, region, resource_id, version, version_position, version_network_interfaces_position, ipv6_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position) DO UPDATE SET ipv6_address=excluded.ipv6_address;

-- name: ListLTVersionNetworkInterfacesIpv6Addresses :many
SELECT * FROM ec2_lt_version_network_interfaces_ipv6_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_network_interfaces_position;

-- name: ClearLTVersionNetworkInterfacesIpv6Addresses :exec
DELETE FROM ec2_lt_version_network_interfaces_ipv6_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionNetworkInterfacesIpv6Prefixes :exec
INSERT INTO ec2_lt_version_network_interfaces_ipv6_prefixes_record (partition, account_id, region, resource_id, version, version_position, version_network_interfaces_position, ipv6_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position) DO UPDATE SET ipv6_prefix=excluded.ipv6_prefix;

-- name: ListLTVersionNetworkInterfacesIpv6Prefixes :many
SELECT * FROM ec2_lt_version_network_interfaces_ipv6_prefixes_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_network_interfaces_position;

-- name: ClearLTVersionNetworkInterfacesIpv6Prefixes :exec
DELETE FROM ec2_lt_version_network_interfaces_ipv6_prefixes_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionNetworkInterfacesPrivateIpAddresses :exec
INSERT INTO ec2_lt_version_network_interfaces_private_ip_addresses_record (partition, account_id, region, resource_id, version, version_position, version_network_interfaces_position, "primary", private_ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_network_interfaces_position) DO UPDATE SET "primary"=excluded."primary", private_ip_address=excluded.private_ip_address;

-- name: ListLTVersionNetworkInterfacesPrivateIpAddresses :many
SELECT * FROM ec2_lt_version_network_interfaces_private_ip_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_network_interfaces_position;

-- name: ClearLTVersionNetworkInterfacesPrivateIpAddresses :exec
DELETE FROM ec2_lt_version_network_interfaces_private_ip_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionSecondaryInterfaces :exec
INSERT INTO ec2_lt_version_secondary_interfaces_record (partition, account_id, region, resource_id, version, version_position, delete_on_termination, device_index, interface_type, network_card_index, private_ip_address_count, private_ip_addresses_present, secondary_subnet_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET delete_on_termination=excluded.delete_on_termination, device_index=excluded.device_index, interface_type=excluded.interface_type, network_card_index=excluded.network_card_index, private_ip_address_count=excluded.private_ip_address_count, private_ip_addresses_present=excluded.private_ip_addresses_present, secondary_subnet_id=excluded.secondary_subnet_id;

-- name: ListLTVersionSecondaryInterfaces :many
SELECT * FROM ec2_lt_version_secondary_interfaces_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionSecondaryInterfaces :exec
DELETE FROM ec2_lt_version_secondary_interfaces_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionSecondaryInterfacesPrivateIpAddresses :exec
INSERT INTO ec2_lt_version_secondary_interfaces_private_ip_addresses_record (partition, account_id, region, resource_id, version, version_position, version_secondary_interfaces_position, private_ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_secondary_interfaces_position) DO UPDATE SET private_ip_address=excluded.private_ip_address;

-- name: ListLTVersionSecondaryInterfacesPrivateIpAddresses :many
SELECT * FROM ec2_lt_version_secondary_interfaces_private_ip_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_secondary_interfaces_position;

-- name: ClearLTVersionSecondaryInterfacesPrivateIpAddresses :exec
DELETE FROM ec2_lt_version_secondary_interfaces_private_ip_addresses_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTVersionSecurityGroupIds :exec
INSERT INTO ec2_lt_version_security_group_ids_record (partition, account_id, region, resource_id, version, version_position, value) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET value=excluded.value;

-- name: ListLTVersionSecurityGroupIds :many
SELECT * FROM ec2_lt_version_security_group_ids_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionSecurityGroupIds :exec
DELETE FROM ec2_lt_version_security_group_ids_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionSecurityGroups :exec
INSERT INTO ec2_lt_version_security_groups_record (partition, account_id, region, resource_id, version, version_position, value) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET value=excluded.value;

-- name: ListLTVersionSecurityGroups :many
SELECT * FROM ec2_lt_version_security_groups_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionSecurityGroups :exec
DELETE FROM ec2_lt_version_security_groups_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionTagSpecifications :exec
INSERT INTO ec2_lt_version_tag_specifications_record (partition, account_id, region, resource_id, version, version_position, resource_type, tags_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position) DO UPDATE SET resource_type=excluded.resource_type, tags_present=excluded.tags_present;

-- name: ListLTVersionTagSpecifications :many
SELECT * FROM ec2_lt_version_tag_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? ORDER BY version_position;

-- name: ClearLTVersionTagSpecifications :exec
DELETE FROM ec2_lt_version_tag_specifications_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ?;

-- name: PutLTVersionTagSpecificationsTags :exec
INSERT INTO ec2_lt_version_tag_specifications_tags_record (partition, account_id, region, resource_id, version, version_position, version_tag_specifications_position, key, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,version,version_position,version_tag_specifications_position) DO UPDATE SET key=excluded.key, value=excluded.value;

-- name: ListLTVersionTagSpecificationsTags :many
SELECT * FROM ec2_lt_version_tag_specifications_tags_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ? ORDER BY version_tag_specifications_position;

-- name: ClearLTVersionTagSpecificationsTags :exec
DELETE FROM ec2_lt_version_tag_specifications_tags_record WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? AND version = ? AND version_position = ?;

-- name: PutLTTemplate :exec
INSERT INTO ec2_launch_template (partition, account_id, region, resource_id, name, created_at, created_by, default_version, latest_version, last_version, tags_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id) DO UPDATE SET name=excluded.name, created_at=excluded.created_at, created_by=excluded.created_by, default_version=excluded.default_version, latest_version=excluded.latest_version, last_version=excluded.last_version, tags_present=excluded.tags_present;

-- name: GetLTTemplate :one
SELECT * FROM ec2_launch_template WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;

-- name: ListLTTemplate :many
SELECT * FROM ec2_launch_template WHERE partition = ? AND account_id = ? AND region = ? ORDER BY resource_id;

-- name: DeleteLTTemplate :execrows
DELETE FROM ec2_launch_template WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;

-- name: PutLTTemplateTag :exec
INSERT INTO ec2_launch_template_tag (partition, account_id, region, resource_id, position, key, value) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (partition,account_id,region,resource_id,position) DO UPDATE SET key=excluded.key, value=excluded.value;

-- name: ListLTTemplateTag :many
SELECT * FROM ec2_launch_template_tag WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ? ORDER BY position;

-- name: ClearLTTemplateTag :exec
DELETE FROM ec2_launch_template_tag WHERE partition = ? AND account_id = ? AND region = ? AND resource_id = ?;

-- name: GetLTToken :one
SELECT * FROM ec2_launch_template_token WHERE partition = ? AND account_id = ? AND region = ? AND action = ? AND token = ?;

-- name: PutLTToken :exec
INSERT INTO ec2_launch_template_token (partition,account_id,region,action,token,fingerprint,resource_id,version) VALUES (?,?,?,?,?,?,?,?);
