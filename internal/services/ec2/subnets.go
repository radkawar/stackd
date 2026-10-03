package ec2

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	api "stackd/internal/awsapi/ec2"
	"strconv"
)

func loadSubnet(ctx context.Context, r Reader, id string) (SubnetRecord, error) {
	v, err := r.Subnet(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		err = missing("subnet", id)
	}
	return v, err
}
func (s *Service) chooseZone(ctx context.Context, in *api.CreateSubnetRequest) (AvailabilityZone, error) {
	if in.AvailabilityZone != nil && in.AvailabilityZoneId != nil {
		return AvailabilityZone{}, failure("InvalidParameterCombination", "The parameter availabilityZone cannot be used with the parameter availabilityZoneId")
	}
	zones, err := s.availableZones(ctx)
	if err != nil {
		return AvailabilityZone{}, err
	}
	for _, zone := range zones {
		if str(zone.OptInStatus) == "not-opted-in" || str(zone.State) != "available" {
			continue
		}
		if (in.AvailabilityZone == nil || str(in.AvailabilityZone) == str(zone.ZoneName)) && (in.AvailabilityZoneId == nil || str(in.AvailabilityZoneId) == str(zone.ZoneId)) {
			return AvailabilityZone{Name: str(zone.ZoneName), ID: str(zone.ZoneId)}, nil
		}
	}
	return AvailabilityZone{}, failure("InvalidParameterValue", "The availability zone is not available in this account and region.")
}
func (s *Service) createSubnet(ctx context.Context, tx Transaction, in *api.CreateSubnetRequest) (*api.CreateSubnetResult, error) {
	if in.Ipv6CidrBlock != nil || boolValue(in.Ipv6Native) || in.Ipv4IpamPoolId != nil || in.Ipv4NetmaskLength != nil || in.Ipv6IpamPoolId != nil || in.Ipv6NetmaskLength != nil || in.OutpostArn != nil {
		return nil, unsupported("IPv6, IPAM, and Outpost subnets are not implemented.")
	}
	vpc, err := loadVPC(ctx, tx, str(in.VpcId))
	if err != nil {
		return nil, err
	}
	cidr, err := canonicalCIDR(str(in.CidrBlock))
	if err != nil {
		return nil, err
	}
	prefix, _ := netip.ParsePrefix(cidr)
	parent, _ := netip.ParsePrefix(str(vpc.Data.CidrBlock))
	if !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 28 || !parent.Contains(prefix.Addr()) || prefix.Bits() < parent.Bits() {
		return nil, failure("InvalidSubnet.Range", "The CIDR '"+str(in.CidrBlock)+"' is invalid.")
	}
	tags, err := CreationTags(in.TagSpecifications, "subnet")
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "CreateSubnet", "vpc", vpc.Key.ID, vpc.Data.Tags); err != nil {
		return nil, err
	}
	if err = s.authorizeCreate(ctx, "CreateSubnet", "subnet", "*", tags); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	existing, err := tx.Subnets(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, v := range existing {
		if str(v.Data.VpcId) != vpc.Key.ID {
			continue
		}
		other, _ := netip.ParsePrefix(str(v.Data.CidrBlock))
		if other.Overlaps(prefix) {
			return nil, failure("InvalidSubnet.Conflict", "The CIDR '"+str(in.CidrBlock)+"' conflicts with another subnet")
		}
	}
	zone, err := s.chooseZone(ctx, in)
	if err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	id, err := tx.NextID(scope, "subnet")
	if err != nil {
		return nil, err
	}
	data := api.Subnet{SubnetId: new(api.String(id)), SubnetArn: new(api.String(resourceARN(scope, "subnet", id))), VpcId: new(api.String(vpc.Key.ID)), CidrBlock: new(api.String(cidr)), AvailabilityZone: new(api.String(zone.Name)), AvailableIpAddressCount: new(api.Integer((1 << uint(32-prefix.Bits())) - 5)), State: new(api.SubnetState("available")), OwnerId: new(api.String(scope.AccountID)), DefaultForAz: new(api.Boolean(false)), MapPublicIpOnLaunch: new(api.Boolean(false)), AssignIpv6AddressOnCreation: new(api.Boolean(false)), MapCustomerOwnedIpOnLaunch: new(api.Boolean(false)), EnableDns64: new(api.Boolean(false)), Ipv6Native: new(api.Boolean(false)), Tags: tags, BlockPublicAccessStates: &api.BlockPublicAccessStates{InternetGatewayBlockMode: new(api.BlockPublicAccessMode("off"))}, PrivateDnsNameOptionsOnLaunch: &api.PrivateDnsNameOptionsOnLaunch{HostnameType: new(api.HostnameType("ip-name")), EnableResourceNameDnsARecord: new(api.Boolean(false)), EnableResourceNameDnsAAAARecord: new(api.Boolean(false))}}
	if zone.ID != "" {
		data.AvailabilityZoneId = new(api.String(zone.ID))
	}
	data.Ipv6CidrBlockAssociationSet = api.SubnetIpv6CidrBlockAssociationSet{}
	if err = tx.PutSubnet(SubnetRecord{Key: ResourceKey{scope, id}, Data: data}); err != nil {
		return nil, err
	}
	acls, err := tx.NetworkACLs(scope)
	if err != nil {
		return nil, err
	}
	associated := false
	for _, acl := range acls {
		if str(acl.Data.VpcId) != vpc.Key.ID || !boolValue(acl.Data.IsDefault) {
			continue
		}
		association, err := tx.NextID(scope, "aclassoc")
		if err != nil {
			return nil, err
		}
		acl.Data.Associations = append(acl.Data.Associations, api.NetworkAclAssociation{NetworkAclAssociationId: new(api.String(association)), NetworkAclId: new(api.String(acl.Key.ID)), SubnetId: new(api.String(id))})
		if err = tx.PutNetworkACL(acl); err != nil {
			return nil, err
		}
		associated = true
		break
	}
	if !associated {
		return nil, errors.New("ec2: VPC has no default ACL")
	}
	data.BlockPublicAccessStates = nil
	return &api.CreateSubnetResult{Subnet: &data}, nil
}
func (s *Service) describeSubnets(ctx context.Context, tx Transaction, in *api.DescribeSubnetsRequest) (*api.DescribeSubnetsResult, error) {
	if err := s.authorize(ctx, "DescribeSubnets", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleSubnets(ctx, tx, "DescribeSubnets")
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := map[string]api.Subnet{}
	for _, v := range records {
		d := v.Data
		count := "0"
		if d.AvailableIpAddressCount != nil {
			count = strconv.Itoa(int(*d.AvailableIpAddressCount))
		}
		items = append(items, pageItem{v.Key.ID, d.Tags, map[string][]string{"subnet-id": {v.Key.ID}, "vpc-id": {str(d.VpcId)}, "cidr": {str(d.CidrBlock)}, "cidr-block": {str(d.CidrBlock)}, "cidrBlock": {str(d.CidrBlock)}, "state": {str(d.State)}, "owner-id": {str(d.OwnerId)}, "availability-zone": {str(d.AvailabilityZone)}, "availability-zone-id": {str(d.AvailabilityZoneId)}, "available-ip-address-count": {count}, "default-for-az": {strconv.FormatBool(boolValue(d.DefaultForAz))}, "defaultForAz": {strconv.FormatBool(boolValue(d.DefaultForAz))}, "map-public-ip-on-launch": {strconv.FormatBool(boolValue(d.MapPublicIpOnLaunch))}}})
		byID[v.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeSubnets", stringsOf(in.SubnetIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeSubnetsResult{Subnets: api.SubnetList{}, NextToken: next}
	for _, id := range ids {
		out.Subnets = append(out.Subnets, byID[id])
	}
	return out, nil
}
func (s *Service) modifySubnetAttribute(ctx context.Context, tx Transaction, in *api.ModifySubnetAttributeRequest) (*emptyResult, error) {
	v, err := loadSubnet(ctx, tx, str(in.SubnetId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "ModifySubnetAttribute", "subnet", v.Key.ID, v.Data.Tags); err != nil {
		return nil, err
	}
	if in.AssignIpv6AddressOnCreation != nil || in.CustomerOwnedIpv4Pool != nil || in.DisableLniAtDeviceIndex != nil || in.EnableLniAtDeviceIndex != nil || in.EnableResourceNameDnsAAAARecordOnLaunch != nil || in.EnableResourceNameDnsARecordOnLaunch != nil || in.MapCustomerOwnedIpOnLaunch != nil || in.PrivateDnsHostnameTypeOnLaunch != nil {
		return nil, unsupported("The requested subnet attribute is not implemented.")
	}
	n := 0
	for _, a := range []*api.AttributeBooleanValue{in.MapPublicIpOnLaunch, in.EnableDns64} {
		if a != nil {
			n++
			if a.Value == nil {
				return nil, failure("MissingParameter", "The attribute value must be specified.")
			}
		}
	}
	if n != 1 {
		return nil, failure("InvalidParameterCombination", "Exactly one subnet attribute must be specified.")
	}
	if in.MapPublicIpOnLaunch != nil {
		v.Data.MapPublicIpOnLaunch = copyPointer(in.MapPublicIpOnLaunch.Value)
	}
	if in.EnableDns64 != nil {
		v.Data.EnableDns64 = copyPointer(in.EnableDns64.Value)
	}
	if err = tx.PutSubnet(v); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
func (s *Service) deleteSubnet(ctx context.Context, tx Transaction, in *api.DeleteSubnetRequest) (*emptyResult, error) {
	v, err := loadSubnet(ctx, tx, str(in.SubnetId))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "DeleteSubnet", "subnet", v.Key.ID, v.Data.Tags); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	interfaces, err := tx.RegionalNetworkInterfaces(v.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, network := range interfaces {
		if interfaceSubnetKey(network) == v.Key {
			return nil, failure("DependencyViolation", "The subnet '"+v.Key.ID+"' has dependencies and cannot be deleted.")
		}
	}
	routes, err := tx.RouteTables(v.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		before := len(r.Data.Associations)
		r.Data.Associations = slices.DeleteFunc(r.Data.Associations, func(a api.RouteTableAssociation) bool { return str(a.SubnetId) == v.Key.ID })
		if before != len(r.Data.Associations) {
			if err = tx.PutRouteTable(r); err != nil {
				return nil, err
			}
		}
	}
	acls, err := tx.NetworkACLs(v.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, a := range acls {
		before := len(a.Data.Associations)
		a.Data.Associations = slices.DeleteFunc(a.Data.Associations, func(x api.NetworkAclAssociation) bool { return str(x.SubnetId) == v.Key.ID })
		if before != len(a.Data.Associations) {
			if err = tx.PutNetworkACL(a); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.DeleteSubnet(v.Key); err != nil {
		return nil, err
	}
	if s.sharedSubnets != nil {
		if err := s.sharedSubnets.SubnetDeleted(ctx, resourceARN(v.Key.Scope, "subnet", v.Key.ID)); err != nil {
			return nil, err
		}
	}
	return &emptyResult{}, nil
}
