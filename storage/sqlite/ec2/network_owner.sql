-- name: GetNatGateway :one
SELECT * FROM ec2_nat_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNatGateways :many
SELECT * FROM ec2_nat_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutNatGateway :exec
INSERT INTO ec2_nat_gateways (partition, account_id, region, resource_id, nat_gateway_id, vpc_id, subnet_id, connectivity_type, availability_mode, state, create_time, delete_time, failure_code, failure_message, tags_present, nat_gateway_addresses_present) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(nat_gateway_id), sqlc.arg(vpc_id), sqlc.arg(subnet_id), sqlc.arg(connectivity_type), sqlc.arg(availability_mode), sqlc.arg(state), sqlc.arg(create_time), sqlc.arg(delete_time), sqlc.arg(failure_code), sqlc.arg(failure_message), sqlc.arg(tags_present), sqlc.arg(nat_gateway_addresses_present)) ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET nat_gateway_id = excluded.nat_gateway_id, vpc_id = excluded.vpc_id, subnet_id = excluded.subnet_id, connectivity_type = excluded.connectivity_type, availability_mode = excluded.availability_mode, state = excluded.state, create_time = excluded.create_time, delete_time = excluded.delete_time, failure_code = excluded.failure_code, failure_message = excluded.failure_message, tags_present = excluded.tags_present, nat_gateway_addresses_present = excluded.nat_gateway_addresses_present;

-- name: DeleteNatGateway :execrows
DELETE FROM ec2_nat_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNatGatewayTags :many
SELECT * FROM ec2_nat_gateway_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNatGatewayTag :exec
INSERT INTO ec2_nat_gateway_tags (partition, account_id, region, resource_id, position, key, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteNatGatewayTags :exec
DELETE FROM ec2_nat_gateway_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNatGatewayAddresses :many
SELECT * FROM ec2_nat_gateway_addresses WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNatGatewayAddress :exec
INSERT INTO ec2_nat_gateway_addresses (partition, account_id, region, resource_id, position, allocation_id, association_id, network_interface_id, private_ip, public_ip, is_primary, status) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(allocation_id), sqlc.arg(association_id), sqlc.arg(network_interface_id), sqlc.arg(private_ip), sqlc.arg(public_ip), sqlc.arg(is_primary), sqlc.arg(status));

-- name: DeleteNatGatewayAddresses :exec
DELETE FROM ec2_nat_gateway_addresses WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetVPCEndpoint :one
SELECT * FROM ec2_vpc_endpoints WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpoints :many
SELECT * FROM ec2_vpc_endpoints WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutVPCEndpoint :exec
INSERT INTO ec2_vpc_endpoints (partition, account_id, region, resource_id, vpc_endpoint_id, vpc_id, vpc_endpoint_type, service_name, service_region, owner_id, requester_managed, state, creation_timestamp, policy_document, private_dns_enabled, ip_address_type, tags_present, groups_present, route_table_ids_present, subnet_ids_present, network_interface_ids_present, dns_entries_present, dns_options_present, dns_record_ip_type, private_dns_only_for_inbound_resolver_endpoint) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(vpc_endpoint_id), sqlc.arg(vpc_id), sqlc.arg(vpc_endpoint_type), sqlc.arg(service_name), sqlc.arg(service_region), sqlc.arg(owner_id), sqlc.arg(requester_managed), sqlc.arg(state), sqlc.arg(creation_timestamp), sqlc.arg(policy_document), sqlc.arg(private_dns_enabled), sqlc.arg(ip_address_type), sqlc.arg(tags_present), sqlc.arg(groups_present), sqlc.arg(route_table_ids_present), sqlc.arg(subnet_ids_present), sqlc.arg(network_interface_ids_present), sqlc.arg(dns_entries_present), sqlc.arg(dns_options_present), sqlc.arg(dns_record_ip_type), sqlc.arg(private_dns_only_for_inbound_resolver_endpoint)) ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET vpc_endpoint_id = excluded.vpc_endpoint_id, vpc_id = excluded.vpc_id, vpc_endpoint_type = excluded.vpc_endpoint_type, service_name = excluded.service_name, service_region = excluded.service_region, owner_id = excluded.owner_id, requester_managed = excluded.requester_managed, state = excluded.state, creation_timestamp = excluded.creation_timestamp, policy_document = excluded.policy_document, private_dns_enabled = excluded.private_dns_enabled, ip_address_type = excluded.ip_address_type, tags_present = excluded.tags_present, groups_present = excluded.groups_present, route_table_ids_present = excluded.route_table_ids_present, subnet_ids_present = excluded.subnet_ids_present, network_interface_ids_present = excluded.network_interface_ids_present, dns_entries_present = excluded.dns_entries_present, dns_options_present = excluded.dns_options_present, dns_record_ip_type = excluded.dns_record_ip_type, private_dns_only_for_inbound_resolver_endpoint = excluded.private_dns_only_for_inbound_resolver_endpoint;

-- name: DeleteVPCEndpoint :execrows
DELETE FROM ec2_vpc_endpoints WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointTags :many
SELECT * FROM ec2_vpc_endpoint_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointTag :exec
INSERT INTO ec2_vpc_endpoint_tags (partition, account_id, region, resource_id, position, key, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteVPCEndpointTags :exec
DELETE FROM ec2_vpc_endpoint_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointGroups :many
SELECT * FROM ec2_vpc_endpoint_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointGroup :exec
INSERT INTO ec2_vpc_endpoint_groups (partition, account_id, region, resource_id, position, group_id, group_name) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(group_id), sqlc.arg(group_name));

-- name: DeleteVPCEndpointGroups :exec
DELETE FROM ec2_vpc_endpoint_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointRouteTables :many
SELECT * FROM ec2_vpc_endpoint_route_tables WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointRouteTable :exec
INSERT INTO ec2_vpc_endpoint_route_tables (partition, account_id, region, resource_id, position, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(value));

-- name: DeleteVPCEndpointRouteTables :exec
DELETE FROM ec2_vpc_endpoint_route_tables WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointSubnets :many
SELECT * FROM ec2_vpc_endpoint_subnets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointSubnet :exec
INSERT INTO ec2_vpc_endpoint_subnets (partition, account_id, region, resource_id, position, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(value));

-- name: DeleteVPCEndpointSubnets :exec
DELETE FROM ec2_vpc_endpoint_subnets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointInterfaces :many
SELECT * FROM ec2_vpc_endpoint_interfaces WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointInterface :exec
INSERT INTO ec2_vpc_endpoint_interfaces (partition, account_id, region, resource_id, position, value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(value));

-- name: DeleteVPCEndpointInterfaces :exec
DELETE FROM ec2_vpc_endpoint_interfaces WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVPCEndpointDNSEntries :many
SELECT * FROM ec2_vpc_endpoint_dns_entries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVPCEndpointDNSEntry :exec
INSERT INTO ec2_vpc_endpoint_dns_entries (partition, account_id, region, resource_id, position, dns_name, hosted_zone_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(dns_name), sqlc.arg(hosted_zone_id));

-- name: DeleteVPCEndpointDNSEntries :exec
DELETE FROM ec2_vpc_endpoint_dns_entries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetNetworkOwnerCreation :one
SELECT * FROM ec2_network_owner_creations WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND action=sqlc.arg(action) AND token=sqlc.arg(token);

-- name: PutNetworkOwnerCreation :exec
INSERT INTO ec2_network_owner_creations(partition,account_id,region,action,token,resource_id,fingerprint) VALUES(sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(action),sqlc.arg(token),sqlc.arg(resource_id),sqlc.arg(fingerprint));

-- name: PutNetworkRelationOwner :exec
INSERT INTO ec2_network_owner_creations(partition,account_id,region,action,token,resource_id,fingerprint)
VALUES(sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(action),'',sqlc.arg(resource_id),sqlc.arg(fingerprint))
ON CONFLICT(partition,account_id,region,action,token) DO UPDATE SET resource_id=excluded.resource_id,fingerprint=excluded.fingerprint;
