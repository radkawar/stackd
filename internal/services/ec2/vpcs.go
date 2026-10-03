package ec2

import (
	"context"
	"errors"
	"net/netip"
	api "stackd/internal/awsapi/ec2"
	"strconv"
)

func loadVPC(ctx context.Context, r Reader, id string) (VPCRecord, error) {
	v, err := r.VPC(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		err = missing("vpc", id)
	}
	return v, err
}
func (s *Service) createVPC(ctx context.Context, tx Transaction, in *api.CreateVpcRequest) (*api.CreateVpcResult, error) {
	if in.Ipv4IpamPoolId != nil || in.Ipv4NetmaskLength != nil || in.Ipv6CidrBlock != nil || in.Ipv6Pool != nil || in.Ipv6IpamPoolId != nil || in.Ipv6NetmaskLength != nil || boolValue(in.AmazonProvidedIpv6CidrBlock) || in.Ipv6CidrBlockNetworkBorderGroup != nil || in.VpcEncryptionControl != nil {
		return nil, unsupported("IPAM, IPv6, and VPC encryption controls are not implemented.")
	}
	cidr, err := canonicalCIDR(str(in.CidrBlock))
	if err != nil {
		return nil, err
	}
	p, _ := netip.ParsePrefix(cidr)
	if !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 28 {
		return nil, failure("InvalidVpc.Range", "The CIDR '"+str(in.CidrBlock)+"' is invalid. The range must be between /16 and /28.")
	}
	tenancy := str(in.InstanceTenancy)
	if tenancy == "" {
		tenancy = "default"
	}
	if tenancy != "default" {
		return nil, unsupported("Only default instance tenancy is supported.")
	}
	tags, err := CreationTags(in.TagSpecifications, "vpc")
	if err != nil {
		return nil, err
	}
	if err = s.authorizeCreate(ctx, "CreateVpc", "vpc", "*", tags); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	id, err := tx.NextID(scope, "vpc")
	if err != nil {
		return nil, err
	}
	association, err := tx.NextID(scope, "vpc-cidr-assoc")
	if err != nil {
		return nil, err
	}
	dhcpOptionsID, err := ensureDefaultDHCPOptions(ctx, tx)
	if err != nil {
		return nil, err
	}
	v := VPCRecord{Key: ResourceKey{scope, id}, DNSSupport: true, Data: api.Vpc{VpcId: new(api.String(id)), CidrBlock: new(api.String(cidr)), State: new(api.VpcState("available")), OwnerId: new(api.String(scope.AccountID)), InstanceTenancy: new(api.Tenancy(tenancy)), IsDefault: new(api.Boolean(false)), Tags: tags, CidrBlockAssociationSet: api.VpcCidrBlockAssociationSet{{AssociationId: new(api.String(association)), CidrBlock: new(api.String(cidr)), CidrBlockState: &api.VpcCidrBlockState{State: new(api.VpcCidrBlockStateCode("associated"))}}}, BlockPublicAccessStates: &api.BlockPublicAccessStates{InternetGatewayBlockMode: new(api.BlockPublicAccessMode("off"))}}}
	v.Data.DhcpOptionsId = new(api.String(dhcpOptionsID))
	if err = tx.PutVPC(v); err != nil {
		return nil, err
	}
	group, err := s.newSecurityGroup(ctx, tx, v, "default", "default VPC security group", nil, true)
	if err != nil {
		return nil, err
	}
	routeID, aclID, err := createDefaultRouting(tx, v)
	if err != nil {
		return nil, err
	}
	if err := s.recordVPCResources(ctx, v.Key, "CreateVpcResourceCreation", aclID, routeID, group.Key.ID); err != nil {
		return nil, err
	}
	v.Data.State = new(api.VpcState("pending"))
	v.Data.BlockPublicAccessStates = nil
	v.Data.Ipv6CidrBlockAssociationSet = api.VpcIpv6CidrBlockAssociationSet{}
	return &api.CreateVpcResult{Vpc: &v.Data}, nil
}
func (s *Service) describeVPCs(ctx context.Context, tx Transaction, in *api.DescribeVpcsRequest) (*api.DescribeVpcsResult, error) {
	if err := s.authorize(ctx, "DescribeVpcs", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleVPCs(ctx, tx, "DescribeVpcs")
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := map[string]api.Vpc{}
	for _, v := range records {
		d := v.Data
		f := map[string][]string{"vpc-id": {v.Key.ID}, "cidr": {str(d.CidrBlock)}, "cidr-block": {str(d.CidrBlock)}, "cidrBlock": {str(d.CidrBlock)}, "state": {str(d.State)}, "owner-id": {str(d.OwnerId)}, "is-default": {strconv.FormatBool(boolValue(d.IsDefault))}, "dhcp-options-id": {str(d.DhcpOptionsId)}, "instance-tenancy": {str(d.InstanceTenancy)}}
		for _, a := range d.CidrBlockAssociationSet {
			f["cidr-block-association.cidr-block"] = append(f["cidr-block-association.cidr-block"], str(a.CidrBlock))
			f["cidr-block-association.association-id"] = append(f["cidr-block-association.association-id"], str(a.AssociationId))
			if a.CidrBlockState != nil {
				f["cidr-block-association.state"] = append(f["cidr-block-association.state"], str(a.CidrBlockState.State))
			}
		}
		items = append(items, pageItem{v.Key.ID, d.Tags, f})
		byID[v.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeVpcs", stringsOf(in.VpcIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeVpcsResult{Vpcs: api.VpcList{}, NextToken: next}
	for _, id := range ids {
		out.Vpcs = append(out.Vpcs, byID[id])
	}
	return out, nil
}
func (s *Service) describeVPCAttribute(ctx context.Context, tx Transaction, in *api.DescribeVpcAttributeRequest) (*api.DescribeVpcAttributeResult, error) {
	v, sharedSubnet, err := s.sharedVPC(ctx, tx, str(in.VpcId), "DescribeVpcAttribute")
	if err != nil {
		return nil, err
	}
	if sharedSubnet.Key.ID == "" {
		if err = s.authorize(ctx, "DescribeVpcAttribute", "vpc", v.Key.ID, v.Data.Tags); err != nil {
			return nil, err
		}
	} else if err := s.authorizeSharedNetwork(ctx, "DescribeVpcAttribute", "vpc", v.Key, sharedSubnet, nil); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	out := &api.DescribeVpcAttributeResult{VpcId: new(api.String(v.Key.ID))}
	switch str(in.Attribute) {
	case "enableDnsSupport":
		out.EnableDnsSupport = &api.AttributeBooleanValue{Value: new(api.Boolean(v.DNSSupport))}
	case "enableDnsHostnames":
		out.EnableDnsHostnames = &api.AttributeBooleanValue{Value: new(api.Boolean(v.DNSHostnames))}
	case "enableNetworkAddressUsageMetrics":
		out.EnableNetworkAddressUsageMetrics = &api.AttributeBooleanValue{Value: new(api.Boolean(v.NetworkAddressUsageMetrics))}
	default:
		return nil, failure("InvalidParameterValue", "Invalid VPC attribute.")
	}
	return out, nil
}
func (s *Service) modifyVPCAttribute(ctx context.Context, tx Transaction, in *api.ModifyVpcAttributeRequest) (*emptyResult, error) {
	v, err := loadVPC(ctx, tx, str(in.VpcId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "ModifyVpcAttribute", "vpc", v.Key.ID, v.Data.Tags); err != nil {
		return nil, err
	}
	n := 0
	for _, a := range []*api.AttributeBooleanValue{in.EnableDnsHostnames, in.EnableDnsSupport, in.EnableNetworkAddressUsageMetrics} {
		if a != nil {
			n++
			if a.Value == nil {
				return nil, failure("MissingParameter", "The attribute value must be specified.")
			}
		}
	}
	if n != 1 {
		return nil, failure("InvalidParameterCombination", "Exactly one VPC attribute must be specified.")
	}
	if in.EnableDnsHostnames != nil {
		v.DNSHostnames = boolValue(in.EnableDnsHostnames.Value)
	}
	if in.EnableDnsSupport != nil {
		v.DNSSupport = boolValue(in.EnableDnsSupport.Value)
	}
	if in.EnableNetworkAddressUsageMetrics != nil {
		v.NetworkAddressUsageMetrics = boolValue(in.EnableNetworkAddressUsageMetrics.Value)
	}
	if err = tx.PutVPC(v); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
func (s *Service) deleteVPC(ctx context.Context, tx Transaction, in *api.DeleteVpcRequest) (*emptyResult, error) {
	v, err := loadVPC(ctx, tx, str(in.VpcId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "DeleteVpc", "vpc", v.Key.ID, v.Data.Tags); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	scope := v.Key.Scope
	subnets, err := tx.Subnets(scope)
	if err != nil {
		return nil, err
	}
	for _, n := range subnets {
		if str(n.Data.VpcId) == v.Key.ID {
			return nil, failure("DependencyViolation", "The vpc '"+v.Key.ID+"' has dependencies and cannot be deleted.")
		}
	}
	gateways, err := tx.InternetGateways(scope)
	if err != nil {
		return nil, err
	}
	for _, gateway := range gateways {
		for _, attachment := range gateway.Data.Attachments {
			if str(attachment.VpcId) == v.Key.ID {
				return nil, failure("DependencyViolation", "The VPC contains an internet gateway.")
			}
		}
	}
	groups, err := tx.RegionalSecurityGroups(scope)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if groupVPCScope(g) == scope && str(g.Data.VpcId) == v.Key.ID && str(g.Data.GroupName) != "default" {
			return nil, failure("DependencyViolation", "The VPC contains a security group.")
		}
	}
	routes, err := tx.RouteTables(scope)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if str(r.Data.VpcId) != v.Key.ID {
			continue
		}
		main := false
		for _, a := range r.Data.Associations {
			main = main || boolValue(a.Main)
		}
		if !main {
			return nil, failure("DependencyViolation", "The VPC contains a route table.")
		}
	}
	acls, err := tx.NetworkACLs(scope)
	if err != nil {
		return nil, err
	}
	for _, a := range acls {
		if str(a.Data.VpcId) == v.Key.ID && !boolValue(a.Data.IsDefault) {
			return nil, failure("DependencyViolation", "The VPC contains a network ACL.")
		}
	}
	rules, err := tx.SecurityGroupRules(scope)
	if err != nil {
		return nil, err
	}
	var groupID, routeID, aclID string
	for _, g := range groups {
		if groupVPCScope(g) != scope || str(g.Data.VpcId) != v.Key.ID {
			continue
		}
		groupID = g.Key.ID
		for _, r := range rules {
			if str(r.Data.GroupId) == g.Key.ID {
				if err = tx.DeleteSecurityGroupRule(r.Key); err != nil {
					return nil, err
				}
			}
		}
		if err = tx.DeleteSecurityGroup(g.Key); err != nil {
			return nil, err
		}
	}
	for _, r := range routes {
		if str(r.Data.VpcId) == v.Key.ID {
			routeID = r.Key.ID
			if err = tx.DeleteRouteTable(r.Key); err != nil {
				return nil, err
			}
		}
	}
	for _, a := range acls {
		if str(a.Data.VpcId) == v.Key.ID {
			aclID = a.Key.ID
			if err = tx.DeleteNetworkACL(a.Key); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.DeleteVPC(v.Key); err != nil {
		return nil, err
	}
	if err := s.recordVPCResources(ctx, v.Key, "DeleteVpcResourceDeletion", aclID, routeID, groupID); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
