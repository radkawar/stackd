-- name: SetVpcCloudFormationOwner :execrows
UPDATE ec2_vpcs SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetSubnetCloudFormationOwner :execrows
UPDATE ec2_subnets SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetSecurityGroupCloudFormationOwner :execrows
UPDATE ec2_security_groups SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetSecurityGroupRuleCloudFormationOwner :execrows
UPDATE ec2_security_group_rules SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetRouteTableCloudFormationOwner :execrows
UPDATE ec2_route_tables SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetInternetGatewayCloudFormationOwner :execrows
UPDATE ec2_internet_gateways SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetNatGatewayCloudFormationOwner :execrows
UPDATE ec2_nat_gateways SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetVPCEndpointCloudFormationOwner :execrows
UPDATE ec2_vpc_endpoints SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetNetworkInterfaceCloudFormationOwner :execrows
UPDATE ec2_network_interfaces SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetNetworkAclCloudFormationOwner :execrows
UPDATE ec2_network_acls SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetDhcpOptionsCloudFormationOwner :execrows
UPDATE ec2_dhcp_options SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetPublicAddressCloudFormationOwner :execrows
UPDATE ec2_public_addresses SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetInstanceCloudFormationOwner :execrows
UPDATE ec2_instances SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetLaunchTemplateCloudFormationOwner :execrows
UPDATE ec2_launch_template SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);

-- name: SetKeyPairCloudFormationOwner :execrows
UPDATE ec2_key_pairs SET cloudformation_resource_type=sqlc.arg(cloudformation_resource_type), cloudformation_owner=sqlc.arg(cloudformation_owner) WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) AND resource_id=sqlc.arg(resource_id);
