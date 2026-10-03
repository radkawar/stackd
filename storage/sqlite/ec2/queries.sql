-- name: GetVpc :one
SELECT * FROM ec2_vpcs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVpcs :many
SELECT * FROM ec2_vpcs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutVpc :exec
INSERT INTO ec2_vpcs (partition, account_id, region, resource_id, block_public_access_states, cidr_block, dhcp_options_id, encryption_control, instance_tenancy, is_default, owner_id, state, vpc_id, dns_hostnames, dns_support, network_address_usage_metrics, tags_present, cidr_block_association_set_present, ipv6_cidr_block_association_set_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(block_public_access_states), sqlc.arg(cidr_block), sqlc.arg(dhcp_options_id), sqlc.arg(encryption_control), sqlc.arg(instance_tenancy), sqlc.arg(is_default), sqlc.arg(owner_id), sqlc.arg(state), sqlc.arg(vpc_id), sqlc.arg(dns_hostnames), sqlc.arg(dns_support), sqlc.arg(network_address_usage_metrics), sqlc.arg(tags_present), sqlc.arg(cidr_block_association_set_present), sqlc.arg(ipv6_cidr_block_association_set_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET block_public_access_states = excluded.block_public_access_states, cidr_block = excluded.cidr_block, dhcp_options_id = excluded.dhcp_options_id, encryption_control = excluded.encryption_control, instance_tenancy = excluded.instance_tenancy, is_default = excluded.is_default, owner_id = excluded.owner_id, state = excluded.state, vpc_id = excluded.vpc_id, dns_hostnames = excluded.dns_hostnames, dns_support = excluded.dns_support, network_address_usage_metrics = excluded.network_address_usage_metrics, tags_present = excluded.tags_present, cidr_block_association_set_present = excluded.cidr_block_association_set_present, ipv6_cidr_block_association_set_present = excluded.ipv6_cidr_block_association_set_present;

-- name: DeleteVpc :execrows
DELETE FROM ec2_vpcs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetSubnet :one
SELECT * FROM ec2_subnets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSubnets :many
SELECT * FROM ec2_subnets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutSubnet :exec
INSERT INTO ec2_subnets (partition, account_id, region, resource_id, assign_ipv6_address_on_creation, availability_zone, availability_zone_id, available_ip_address_count, block_public_access_states, cidr_block, customer_owned_ipv4_pool, default_for_az, enable_dns64, enable_lni_at_device_index, ipv6_native, map_customer_owned_ip_on_launch, map_public_ip_on_launch, outpost_arn, owner_id, private_dns_name_options_on_launch, state, subnet_arn, subnet_id, type, vpc_id, tags_present, ipv6_cidr_block_association_set_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(assign_ipv6_address_on_creation), sqlc.arg(availability_zone), sqlc.arg(availability_zone_id), sqlc.arg(available_ip_address_count), sqlc.arg(block_public_access_states), sqlc.arg(cidr_block), sqlc.arg(customer_owned_ipv4_pool), sqlc.arg(default_for_az), sqlc.arg(enable_dns64), sqlc.arg(enable_lni_at_device_index), sqlc.arg(ipv6_native), sqlc.arg(map_customer_owned_ip_on_launch), sqlc.arg(map_public_ip_on_launch), sqlc.arg(outpost_arn), sqlc.arg(owner_id), sqlc.arg(private_dns_name_options_on_launch), sqlc.arg(state), sqlc.arg(subnet_arn), sqlc.arg(subnet_id), sqlc.arg(type), sqlc.arg(vpc_id), sqlc.arg(tags_present), sqlc.arg(ipv6_cidr_block_association_set_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET assign_ipv6_address_on_creation = excluded.assign_ipv6_address_on_creation, availability_zone = excluded.availability_zone, availability_zone_id = excluded.availability_zone_id, available_ip_address_count = excluded.available_ip_address_count, block_public_access_states = excluded.block_public_access_states, cidr_block = excluded.cidr_block, customer_owned_ipv4_pool = excluded.customer_owned_ipv4_pool, default_for_az = excluded.default_for_az, enable_dns64 = excluded.enable_dns64, enable_lni_at_device_index = excluded.enable_lni_at_device_index, ipv6_native = excluded.ipv6_native, map_customer_owned_ip_on_launch = excluded.map_customer_owned_ip_on_launch, map_public_ip_on_launch = excluded.map_public_ip_on_launch, outpost_arn = excluded.outpost_arn, owner_id = excluded.owner_id, private_dns_name_options_on_launch = excluded.private_dns_name_options_on_launch, state = excluded.state, subnet_arn = excluded.subnet_arn, subnet_id = excluded.subnet_id, type = excluded.type, vpc_id = excluded.vpc_id, tags_present = excluded.tags_present, ipv6_cidr_block_association_set_present = excluded.ipv6_cidr_block_association_set_present;

-- name: DeleteSubnet :execrows
DELETE FROM ec2_subnets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetSecurityGroup :one
SELECT * FROM ec2_security_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSecurityGroups :many
SELECT * FROM ec2_security_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutSecurityGroup :exec
INSERT INTO ec2_security_groups (partition, account_id, region, resource_id, vpc_owner_account_id, description, group_id, group_name, owner_id, security_group_arn, vpc_id, tags_present, ip_permissions_present, ip_permissions_egress_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(vpc_owner_account_id), sqlc.arg(description), sqlc.arg(group_id), sqlc.arg(group_name), sqlc.arg(owner_id), sqlc.arg(security_group_arn), sqlc.arg(vpc_id), sqlc.arg(tags_present), sqlc.arg(ip_permissions_present), sqlc.arg(ip_permissions_egress_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET vpc_owner_account_id = excluded.vpc_owner_account_id, description = excluded.description, group_id = excluded.group_id, group_name = excluded.group_name, owner_id = excluded.owner_id, security_group_arn = excluded.security_group_arn, vpc_id = excluded.vpc_id, tags_present = excluded.tags_present, ip_permissions_present = excluded.ip_permissions_present, ip_permissions_egress_present = excluded.ip_permissions_egress_present;

-- name: DeleteSecurityGroup :execrows
DELETE FROM ec2_security_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetSecurityGroupRule :one
SELECT * FROM ec2_security_group_rules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSecurityGroupRules :many
SELECT * FROM ec2_security_group_rules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutSecurityGroupRule :exec
INSERT INTO ec2_security_group_rules (partition, account_id, region, resource_id, cidr_ipv4, cidr_ipv6, description, from_port, group_id, group_owner_id, ip_protocol, is_egress, prefix_list_id, referenced_group_info, security_group_rule_arn, security_group_rule_id, to_port, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(cidr_ipv4), sqlc.arg(cidr_ipv6), sqlc.arg(description), sqlc.arg(from_port), sqlc.arg(group_id), sqlc.arg(group_owner_id), sqlc.arg(ip_protocol), sqlc.arg(is_egress), sqlc.arg(prefix_list_id), sqlc.arg(referenced_group_info), sqlc.arg(security_group_rule_arn), sqlc.arg(security_group_rule_id), sqlc.arg(to_port), sqlc.arg(tags_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET cidr_ipv4 = excluded.cidr_ipv4, cidr_ipv6 = excluded.cidr_ipv6, description = excluded.description, from_port = excluded.from_port, group_id = excluded.group_id, group_owner_id = excluded.group_owner_id, ip_protocol = excluded.ip_protocol, is_egress = excluded.is_egress, prefix_list_id = excluded.prefix_list_id, referenced_group_info = excluded.referenced_group_info, security_group_rule_arn = excluded.security_group_rule_arn, security_group_rule_id = excluded.security_group_rule_id, to_port = excluded.to_port, tags_present = excluded.tags_present;

-- name: DeleteSecurityGroupRule :execrows
DELETE FROM ec2_security_group_rules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetRouteTable :one
SELECT * FROM ec2_route_tables WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListRouteTables :many
SELECT * FROM ec2_route_tables WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutRouteTable :exec
INSERT INTO ec2_route_tables (partition, account_id, region, resource_id, owner_id, route_table_id, vpc_id, tags_present, associations_present, propagating_vgws_present, routes_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(owner_id), sqlc.arg(route_table_id), sqlc.arg(vpc_id), sqlc.arg(tags_present), sqlc.arg(associations_present), sqlc.arg(propagating_vgws_present), sqlc.arg(routes_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET owner_id = excluded.owner_id, route_table_id = excluded.route_table_id, vpc_id = excluded.vpc_id, tags_present = excluded.tags_present, associations_present = excluded.associations_present, propagating_vgws_present = excluded.propagating_vgws_present, routes_present = excluded.routes_present;

-- name: DeleteRouteTable :execrows
DELETE FROM ec2_route_tables WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetNetworkAcl :one
SELECT * FROM ec2_network_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkAcls :many
SELECT * FROM ec2_network_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutNetworkAcl :exec
INSERT INTO ec2_network_acls (partition, account_id, region, resource_id, is_default, network_acl_id, owner_id, vpc_id, tags_present, associations_present, entries_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(is_default), sqlc.arg(network_acl_id), sqlc.arg(owner_id), sqlc.arg(vpc_id), sqlc.arg(tags_present), sqlc.arg(associations_present), sqlc.arg(entries_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET is_default = excluded.is_default, network_acl_id = excluded.network_acl_id, owner_id = excluded.owner_id, vpc_id = excluded.vpc_id, tags_present = excluded.tags_present, associations_present = excluded.associations_present, entries_present = excluded.entries_present;

-- name: DeleteNetworkAcl :execrows
DELETE FROM ec2_network_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVpcTags :many
SELECT * FROM ec2_vpc_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVpcTag :exec
INSERT INTO ec2_vpc_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteVpcTags :exec
DELETE FROM ec2_vpc_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSubnetTags :many
SELECT * FROM ec2_subnet_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutSubnetTag :exec
INSERT INTO ec2_subnet_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteSubnetTags :exec
DELETE FROM ec2_subnet_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSecurityGroupTags :many
SELECT * FROM ec2_security_group_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutSecurityGroupTag :exec
INSERT INTO ec2_security_group_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteSecurityGroupTags :exec
DELETE FROM ec2_security_group_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSecurityGroupRuleTags :many
SELECT * FROM ec2_security_group_rule_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutSecurityGroupRuleTag :exec
INSERT INTO ec2_security_group_rule_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteSecurityGroupRuleTags :exec
DELETE FROM ec2_security_group_rule_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListRouteTableTags :many
SELECT * FROM ec2_route_table_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutRouteTableTag :exec
INSERT INTO ec2_route_table_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteRouteTableTags :exec
DELETE FROM ec2_route_table_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkAclTags :many
SELECT * FROM ec2_network_acl_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkAclTag :exec
INSERT INTO ec2_network_acl_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET key = excluded.key, value = excluded.value;

-- name: DeleteNetworkAclTags :exec
DELETE FROM ec2_network_acl_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVpcCidrAssociations :many
SELECT * FROM ec2_vpc_cidr_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVpcCidrAssociation :exec
INSERT INTO ec2_vpc_cidr_associations (partition, account_id, region, resource_id, position, association_id, cidr_block, cidr_block_state)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(association_id), sqlc.arg(cidr_block), sqlc.arg(cidr_block_state))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET association_id = excluded.association_id, cidr_block = excluded.cidr_block, cidr_block_state = excluded.cidr_block_state;

-- name: DeleteVpcCidrAssociations :exec
DELETE FROM ec2_vpc_cidr_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListVpcIpv6Associations :many
SELECT * FROM ec2_vpc_ipv6_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutVpcIpv6Association :exec
INSERT INTO ec2_vpc_ipv6_associations (partition, account_id, region, resource_id, position, association_id, ip_source, ipv6_address_attribute, ipv6_cidr_block, ipv6_cidr_block_state, ipv6_pool, network_border_group)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(association_id), sqlc.arg(ip_source), sqlc.arg(ipv6_address_attribute), sqlc.arg(ipv6_cidr_block), sqlc.arg(ipv6_cidr_block_state), sqlc.arg(ipv6_pool), sqlc.arg(network_border_group))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET association_id = excluded.association_id, ip_source = excluded.ip_source, ipv6_address_attribute = excluded.ipv6_address_attribute, ipv6_cidr_block = excluded.ipv6_cidr_block, ipv6_cidr_block_state = excluded.ipv6_cidr_block_state, ipv6_pool = excluded.ipv6_pool, network_border_group = excluded.network_border_group;

-- name: DeleteVpcIpv6Associations :exec
DELETE FROM ec2_vpc_ipv6_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSubnetIpv6Associations :many
SELECT * FROM ec2_subnet_ipv6_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutSubnetIpv6Association :exec
INSERT INTO ec2_subnet_ipv6_associations (partition, account_id, region, resource_id, position, association_id, ip_source, ipv6_address_attribute, ipv6_cidr_block, ipv6_cidr_block_state)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(association_id), sqlc.arg(ip_source), sqlc.arg(ipv6_address_attribute), sqlc.arg(ipv6_cidr_block), sqlc.arg(ipv6_cidr_block_state))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET association_id = excluded.association_id, ip_source = excluded.ip_source, ipv6_address_attribute = excluded.ipv6_address_attribute, ipv6_cidr_block = excluded.ipv6_cidr_block, ipv6_cidr_block_state = excluded.ipv6_cidr_block_state;

-- name: DeleteSubnetIpv6Associations :exec
DELETE FROM ec2_subnet_ipv6_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListSecurityGroupPermissions :many
SELECT * FROM ec2_security_group_permissions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) AND egress = sqlc.arg(egress) ORDER BY position;

-- name: PutSecurityGroupPermission :exec
INSERT INTO ec2_security_group_permissions (partition, account_id, region, resource_id, egress, position, from_port, ip_protocol, ip_ranges, ipv6_ranges, prefix_list_ids, to_port, user_id_group_pairs)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(egress), sqlc.arg(position), sqlc.arg(from_port), sqlc.arg(ip_protocol), sqlc.arg(ip_ranges), sqlc.arg(ipv6_ranges), sqlc.arg(prefix_list_ids), sqlc.arg(to_port), sqlc.arg(user_id_group_pairs))
ON CONFLICT (partition, account_id, region, resource_id, egress, position) DO UPDATE SET from_port = excluded.from_port, ip_protocol = excluded.ip_protocol, ip_ranges = excluded.ip_ranges, ipv6_ranges = excluded.ipv6_ranges, prefix_list_ids = excluded.prefix_list_ids, to_port = excluded.to_port, user_id_group_pairs = excluded.user_id_group_pairs;

-- name: DeleteSecurityGroupPermissions :exec
DELETE FROM ec2_security_group_permissions WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) AND egress = sqlc.arg(egress);

-- name: ListRouteTableAssociations :many
SELECT * FROM ec2_route_table_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutRouteTableAssociation :exec
INSERT INTO ec2_route_table_associations (partition, account_id, region, resource_id, position, association_state, gateway_id, main, public_ipv4_pool, route_table_association_id, route_table_id, subnet_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(association_state), sqlc.arg(gateway_id), sqlc.arg(main), sqlc.arg(public_ipv4_pool), sqlc.arg(route_table_association_id), sqlc.arg(route_table_id), sqlc.arg(subnet_id))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET association_state = excluded.association_state, gateway_id = excluded.gateway_id, main = excluded.main, public_ipv4_pool = excluded.public_ipv4_pool, route_table_association_id = excluded.route_table_association_id, route_table_id = excluded.route_table_id, subnet_id = excluded.subnet_id;

-- name: DeleteRouteTableAssociations :exec
DELETE FROM ec2_route_table_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListRouteTablePropagations :many
SELECT * FROM ec2_route_table_propagations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutRouteTablePropagation :exec
INSERT INTO ec2_route_table_propagations (partition, account_id, region, resource_id, position, gateway_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(gateway_id))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET gateway_id = excluded.gateway_id;

-- name: DeleteRouteTablePropagations :exec
DELETE FROM ec2_route_table_propagations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListRouteTableRoutes :many
SELECT * FROM ec2_route_table_routes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutRouteTableRoute :exec
INSERT INTO ec2_route_table_routes (partition, account_id, region, resource_id, position, carrier_gateway_id, core_network_arn, destination_cidr_block, destination_ipv6_cidr_block, destination_prefix_list_id, egress_only_internet_gateway_id, gateway_id, instance_id, instance_owner_id, ip_address, local_gateway_id, nat_gateway_id, network_interface_id, odb_network_arn, origin, state, transit_gateway_id, vpc_peering_connection_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(carrier_gateway_id), sqlc.arg(core_network_arn), sqlc.arg(destination_cidr_block), sqlc.arg(destination_ipv6_cidr_block), sqlc.arg(destination_prefix_list_id), sqlc.arg(egress_only_internet_gateway_id), sqlc.arg(gateway_id), sqlc.arg(instance_id), sqlc.arg(instance_owner_id), sqlc.arg(ip_address), sqlc.arg(local_gateway_id), sqlc.arg(nat_gateway_id), sqlc.arg(network_interface_id), sqlc.arg(odb_network_arn), sqlc.arg(origin), sqlc.arg(state), sqlc.arg(transit_gateway_id), sqlc.arg(vpc_peering_connection_id))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET carrier_gateway_id = excluded.carrier_gateway_id, core_network_arn = excluded.core_network_arn, destination_cidr_block = excluded.destination_cidr_block, destination_ipv6_cidr_block = excluded.destination_ipv6_cidr_block, destination_prefix_list_id = excluded.destination_prefix_list_id, egress_only_internet_gateway_id = excluded.egress_only_internet_gateway_id, gateway_id = excluded.gateway_id, instance_id = excluded.instance_id, instance_owner_id = excluded.instance_owner_id, ip_address = excluded.ip_address, local_gateway_id = excluded.local_gateway_id, nat_gateway_id = excluded.nat_gateway_id, network_interface_id = excluded.network_interface_id, odb_network_arn = excluded.odb_network_arn, origin = excluded.origin, state = excluded.state, transit_gateway_id = excluded.transit_gateway_id, vpc_peering_connection_id = excluded.vpc_peering_connection_id;

-- name: DeleteRouteTableRoutes :exec
DELETE FROM ec2_route_table_routes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkAclAssociations :many
SELECT * FROM ec2_network_acl_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkAclAssociation :exec
INSERT INTO ec2_network_acl_associations (partition, account_id, region, resource_id, position, network_acl_association_id, network_acl_id, subnet_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(network_acl_association_id), sqlc.arg(network_acl_id), sqlc.arg(subnet_id))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET network_acl_association_id = excluded.network_acl_association_id, network_acl_id = excluded.network_acl_id, subnet_id = excluded.subnet_id;

-- name: DeleteNetworkAclAssociations :exec
DELETE FROM ec2_network_acl_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkAclEntrys :many
SELECT * FROM ec2_network_acl_entries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkAclEntry :exec
INSERT INTO ec2_network_acl_entries (partition, account_id, region, resource_id, position, cidr_block, egress, icmp_type_code, ipv6_cidr_block, port_range, protocol, rule_action, rule_number)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(cidr_block), sqlc.arg(egress), sqlc.arg(icmp_type_code), sqlc.arg(ipv6_cidr_block), sqlc.arg(port_range), sqlc.arg(protocol), sqlc.arg(rule_action), sqlc.arg(rule_number))
ON CONFLICT (partition, account_id, region, resource_id, position) DO UPDATE SET cidr_block = excluded.cidr_block, egress = excluded.egress, icmp_type_code = excluded.icmp_type_code, ipv6_cidr_block = excluded.ipv6_cidr_block, port_range = excluded.port_range, protocol = excluded.protocol, rule_action = excluded.rule_action, rule_number = excluded.rule_number;

-- name: DeleteNetworkAclEntrys :exec
DELETE FROM ec2_network_acl_entries WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetSequence :one
SELECT sequence FROM ec2_sequences WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND prefix = sqlc.arg(prefix);

-- name: PutSequence :exec
INSERT INTO ec2_sequences (partition, account_id, region, prefix, sequence)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(prefix), sqlc.arg(sequence))
ON CONFLICT (partition, account_id, region, prefix) DO UPDATE SET sequence = excluded.sequence;

-- name: GetDhcpDefaults :one
SELECT * FROM ec2_dhcp_defaults WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region);

-- name: PutDhcpDefaults :exec
INSERT INTO ec2_dhcp_defaults (partition, account_id, region, options_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(options_id))
ON CONFLICT (partition, account_id, region) DO UPDATE SET options_id = excluded.options_id;

-- name: GetDhcpOptions :one
SELECT * FROM ec2_dhcp_options WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListDhcpOptions :many
SELECT * FROM ec2_dhcp_options WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutDhcpOptions :exec
INSERT INTO ec2_dhcp_options (partition, account_id, region, resource_id, dhcp_options_id, owner_id, tags_present, configurations_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(dhcp_options_id), sqlc.arg(owner_id), sqlc.arg(tags_present), sqlc.arg(configurations_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET dhcp_options_id = excluded.dhcp_options_id, owner_id = excluded.owner_id, tags_present = excluded.tags_present, configurations_present = excluded.configurations_present;

-- name: DeleteDhcpOptions :execrows
DELETE FROM ec2_dhcp_options WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListDhcpOptionsTags :many
SELECT * FROM ec2_dhcp_options_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutDhcpOptionsTag :exec
INSERT INTO ec2_dhcp_options_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteDhcpOptionsTags :exec
DELETE FROM ec2_dhcp_options_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListDhcpConfigurations :many
SELECT * FROM ec2_dhcp_configurations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutDhcpConfiguration :exec
INSERT INTO ec2_dhcp_configurations (partition, account_id, region, resource_id, position, key, values_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(values_present));

-- name: DeleteDhcpConfigurations :exec
DELETE FROM ec2_dhcp_configurations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListDhcpConfigurationValues :many
SELECT * FROM ec2_dhcp_configuration_values WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) AND configuration_position = sqlc.arg(configuration_position) ORDER BY position;

-- name: PutDhcpConfigurationValue :exec
INSERT INTO ec2_dhcp_configuration_values (partition, account_id, region, resource_id, configuration_position, position, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(configuration_position), sqlc.arg(position), sqlc.arg(value));

-- name: GetNetworkCreation :one
SELECT * FROM ec2_network_creations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND action = sqlc.arg(action) AND token = sqlc.arg(token);

-- name: PutNetworkCreation :exec
INSERT INTO ec2_network_creations (partition, account_id, region, action, token, vpc_id, resource_id, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(action), sqlc.arg(token), sqlc.arg(vpc_id), sqlc.arg(resource_id), sqlc.arg(tags_present));

-- name: ListNetworkCreationTags :many
SELECT * FROM ec2_network_creation_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND action = sqlc.arg(action) AND token = sqlc.arg(token) ORDER BY position;

-- name: PutNetworkCreationTag :exec
INSERT INTO ec2_network_creation_tags (partition, account_id, region, action, token, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(action), sqlc.arg(token), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: GetInternetGateway :one
SELECT * FROM ec2_internet_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListInternetGateways :many
SELECT * FROM ec2_internet_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutInternetGateway :exec
INSERT INTO ec2_internet_gateways (partition, account_id, region, resource_id, internet_gateway_id, owner_id, attachments_present, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(internet_gateway_id), sqlc.arg(owner_id), sqlc.arg(attachments_present), sqlc.arg(tags_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET internet_gateway_id = excluded.internet_gateway_id, owner_id = excluded.owner_id, attachments_present = excluded.attachments_present, tags_present = excluded.tags_present;

-- name: DeleteInternetGateway :execrows
DELETE FROM ec2_internet_gateways WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListInternetGatewayAttachments :many
SELECT * FROM ec2_internet_gateway_attachments WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutInternetGatewayAttachment :exec
INSERT INTO ec2_internet_gateway_attachments (partition, account_id, region, resource_id, position, state, vpc_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(state), sqlc.arg(vpc_id));

-- name: DeleteInternetGatewayAttachments :exec
DELETE FROM ec2_internet_gateway_attachments WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListInternetGatewayTags :many
SELECT * FROM ec2_internet_gateway_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutInternetGatewayTag :exec
INSERT INTO ec2_internet_gateway_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteInternetGatewayTags :exec
DELETE FROM ec2_internet_gateway_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetNetworkInterface :one
SELECT * FROM ec2_network_interfaces WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkInterfaces :many
SELECT * FROM ec2_network_interfaces WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutNetworkInterface :exec
INSERT INTO ec2_network_interfaces (
 subnet_owner_account_id,
 lambda_mapping_owner_arn,
 partition, account_id, region, resource_id, network_interface_id, owner_id, requester_id, requester_managed,
 availability_zone, availability_zone_id, subnet_id, vpc_id, mac_address, description, interface_type,
 source_dest_check, status, private_ip_address, private_dns_name, groups_present, private_ip_addresses_present,
 ipv6_addresses_present, tags_present, operator_present, operator_managed, operator_hidden_by_default, operator_principal,
 task_owner_arn, task_public_networking, attachment_present, attachment_id, attachment_time, attachment_delete_on_termination,
 attachment_device_index, attachment_network_card_index, attachment_status, attachment_instance_id, attachment_instance_owner_id
)
VALUES (
 sqlc.arg(subnet_owner_account_id),
 sqlc.arg(lambda_mapping_owner_arn),
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(network_interface_id),
 sqlc.arg(owner_id), sqlc.arg(requester_id), sqlc.arg(requester_managed), sqlc.arg(availability_zone),
 sqlc.arg(availability_zone_id), sqlc.arg(subnet_id), sqlc.arg(vpc_id), sqlc.arg(mac_address), sqlc.arg(description),
 sqlc.arg(interface_type), sqlc.arg(source_dest_check), sqlc.arg(status), sqlc.arg(private_ip_address),
 sqlc.arg(private_dns_name), sqlc.arg(groups_present), sqlc.arg(private_ip_addresses_present), sqlc.arg(ipv6_addresses_present),
 sqlc.arg(tags_present), sqlc.arg(operator_present), sqlc.arg(operator_managed), sqlc.arg(operator_hidden_by_default),
 sqlc.arg(operator_principal), sqlc.arg(task_owner_arn), sqlc.arg(task_public_networking),
 sqlc.arg(attachment_present), sqlc.arg(attachment_id), sqlc.arg(attachment_time), sqlc.arg(attachment_delete_on_termination),
 sqlc.arg(attachment_device_index), sqlc.arg(attachment_network_card_index), sqlc.arg(attachment_status), sqlc.arg(attachment_instance_id), sqlc.arg(attachment_instance_owner_id)
)
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET
 subnet_owner_account_id = excluded.subnet_owner_account_id,
 network_interface_id = excluded.network_interface_id, owner_id = excluded.owner_id, requester_id = excluded.requester_id,
 requester_managed = excluded.requester_managed, availability_zone = excluded.availability_zone, availability_zone_id = excluded.availability_zone_id,
 subnet_id = excluded.subnet_id, vpc_id = excluded.vpc_id, mac_address = excluded.mac_address, description = excluded.description,
 interface_type = excluded.interface_type, source_dest_check = excluded.source_dest_check, status = excluded.status,
 private_ip_address = excluded.private_ip_address, private_dns_name = excluded.private_dns_name, groups_present = excluded.groups_present,
 private_ip_addresses_present = excluded.private_ip_addresses_present, ipv6_addresses_present = excluded.ipv6_addresses_present,
 tags_present = excluded.tags_present, operator_present = excluded.operator_present, operator_managed = excluded.operator_managed,
 operator_hidden_by_default = excluded.operator_hidden_by_default, operator_principal = excluded.operator_principal,
 task_owner_arn = excluded.task_owner_arn, task_public_networking = excluded.task_public_networking,
 attachment_present = excluded.attachment_present, attachment_id = excluded.attachment_id, attachment_time = excluded.attachment_time,
 attachment_delete_on_termination = excluded.attachment_delete_on_termination, attachment_device_index = excluded.attachment_device_index,
 attachment_network_card_index = excluded.attachment_network_card_index, attachment_status = excluded.attachment_status,
 attachment_instance_id = excluded.attachment_instance_id, attachment_instance_owner_id = excluded.attachment_instance_owner_id;

-- name: DeleteNetworkInterface :execrows
DELETE FROM ec2_network_interfaces WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkInterfaceGroups :many
SELECT * FROM ec2_network_interface_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkInterfaceGroup :exec
INSERT INTO ec2_network_interface_groups (partition, account_id, region, resource_id, position, group_id, group_name)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(group_id), sqlc.arg(group_name));

-- name: DeleteNetworkInterfaceGroups :exec
DELETE FROM ec2_network_interface_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkInterfacePrivateIPs :many
SELECT * FROM ec2_network_interface_private_ips WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkInterfacePrivateIP :exec
INSERT INTO ec2_network_interface_private_ips (partition, account_id, region, resource_id, position, private_ip_address, is_primary, private_dns_name)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(private_ip_address), sqlc.arg(is_primary), sqlc.arg(private_dns_name));

-- name: DeleteNetworkInterfacePrivateIPs :exec
DELETE FROM ec2_network_interface_private_ips WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListNetworkInterfaceTags :many
SELECT * FROM ec2_network_interface_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutNetworkInterfaceTag :exec
INSERT INTO ec2_network_interface_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteNetworkInterfaceTags :exec
DELETE FROM ec2_network_interface_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: GetNetworkInterfaceCreation :one
SELECT * FROM ec2_network_interface_creations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutNetworkInterfaceCreation :exec
INSERT INTO ec2_network_interface_creations (
 partition, account_id, region, token, resource_id, subnet_id, description, interface_type, private_ip_address,
 secondary_private_ip_address_count, groups_present, private_ip_addresses_present
)
VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(resource_id), sqlc.arg(subnet_id),
 sqlc.arg(description), sqlc.arg(interface_type), sqlc.arg(private_ip_address), sqlc.arg(secondary_private_ip_address_count),
 sqlc.arg(groups_present), sqlc.arg(private_ip_addresses_present)
)
ON CONFLICT (partition, account_id, region, token) DO UPDATE SET
 resource_id = excluded.resource_id, subnet_id = excluded.subnet_id, description = excluded.description,
 interface_type = excluded.interface_type, private_ip_address = excluded.private_ip_address,
 secondary_private_ip_address_count = excluded.secondary_private_ip_address_count, groups_present = excluded.groups_present,
 private_ip_addresses_present = excluded.private_ip_addresses_present;

-- name: ListNetworkInterfaceCreationGroups :many
SELECT * FROM ec2_network_interface_creation_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: PutNetworkInterfaceCreationGroup :exec
INSERT INTO ec2_network_interface_creation_groups (partition, account_id, region, token, position, group_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(group_id));

-- name: DeleteNetworkInterfaceCreationGroups :exec
DELETE FROM ec2_network_interface_creation_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: ListNetworkInterfaceCreationPrivateIPs :many
SELECT * FROM ec2_network_interface_creation_private_ips WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: PutNetworkInterfaceCreationPrivateIP :exec
INSERT INTO ec2_network_interface_creation_private_ips (partition, account_id, region, token, position, private_ip_address, is_primary)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(private_ip_address), sqlc.arg(is_primary));

-- name: DeleteNetworkInterfaceCreationPrivateIPs :exec
DELETE FROM ec2_network_interface_creation_private_ips WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: ListRegionalNetworkInterfaces :many
SELECT * FROM ec2_network_interfaces WHERE partition = sqlc.arg(partition) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: ListRegionalSecurityGroups :many
SELECT * FROM ec2_security_groups WHERE partition = sqlc.arg(partition) AND region = sqlc.arg(region) ORDER BY resource_id;
