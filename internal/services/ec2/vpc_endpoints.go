package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
)

const defaultEndpointPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`

func endpointPolicy(document *api.String) (*api.String, error) {
	if document == nil {
		return new(api.String(defaultEndpointPolicy)), nil
	}
	if len(str(document)) > 20480 || authorization.ValidateResourcePolicy([]byte(str(document))) != nil {
		return nil, failure("InvalidPolicyDocument", "PolicyDocument must be a valid IAM resource policy of at most 20480 bytes.")
	}
	return copyPointer(document), nil
}
func endpointDNS(kind string, enabled *api.Boolean, options *api.DnsOptionsSpecification, ipType *api.IpAddressType) (*api.DnsOptions, error) {
	if ipType != nil && str(ipType) != "ipv4" {
		return nil, unsupported("Endpoint controls currently allocate IPv4 addresses only.")
	}
	if kind == "Gateway" && (boolValue(enabled) || options != nil) {
		return nil, failure("InvalidParameterCombination", "Gateway endpoints do not support private DNS configuration.")
	}
	if options == nil {
		return nil, nil
	}
	if options.DnsRecordIpType != nil && str(options.DnsRecordIpType) != "ipv4" && str(options.DnsRecordIpType) != "service-defined" {
		return nil, unsupported("Only IPv4 endpoint DNS records are supported.")
	}
	if options.PrivateDnsPreference != nil || len(options.PrivateDnsSpecifiedDomains) > 0 {
		return nil, unsupported("Endpoint private DNS preference and specified domains are not supported.")
	}
	return &api.DnsOptions{DnsRecordIpType: copyPointer(options.DnsRecordIpType), PrivateDnsOnlyForInboundResolverEndpoint: copyPointer(options.PrivateDnsOnlyForInboundResolverEndpoint)}, nil
}
func endpointPrefixList(scope Scope, service string) string {
	sum := sha256.Sum256([]byte(scope.Partition + "/" + scope.Region + "/" + service))
	return fmt.Sprintf("pl-%x", sum[:8])
}
func (s *Service) endpointForAction(ctx context.Context, tx Reader, action, id string) (VPCEndpointRecord, error) {
	v, err := tx.VPCEndpoint(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return v, networkOwnerMissing("vpc-endpoint", id)
	}
	if err != nil {
		return v, err
	}
	return v, s.authorizeWith(ctx, action, "vpc-endpoint", id, v.Data.Tags, vpcConditions(scopeFor(ctx), str(v.Data.VpcId)))
}
func (s *Service) validateEndpointRoutes(ctx context.Context, tx Reader, action, vpc string, ids api.ValueStringList) ([]RouteTableRecord, error) {
	out := make([]RouteTableRecord, 0, len(ids))
	for _, id := range ids {
		v, err := tx.RouteTable(key(ctx, string(id)))
		if errors.Is(err, ErrNotFound) {
			return nil, missing("route-table", string(id))
		}
		if err != nil {
			return nil, err
		}
		if err = s.authorizeWith(ctx, action, "route-table", string(id), v.Data.Tags, vpcConditions(scopeFor(ctx), str(v.Data.VpcId))); err != nil {
			return nil, err
		}
		if str(v.Data.VpcId) != vpc {
			return nil, failure("InvalidParameterValue", "Endpoint route table belongs to a different VPC.")
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Service) endpointSubnets(ctx context.Context, tx Reader, action, vpc string, ids api.ValueStringList) ([]SubnetRecord, error) {
	out := make([]SubnetRecord, 0, len(ids))
	zones := map[string]bool{}
	for _, id := range ids {
		subnet, err := s.subnetForUse(ctx, tx, string(id), action)
		if err != nil {
			return nil, err
		}
		if subnet.Key.ID == "" {
			return nil, missing("subnet", string(id))
		}
		if subnet.Key.Scope != scopeFor(ctx) || str(subnet.Data.VpcId) != vpc {
			return nil, failure("InvalidParameterValue", "Endpoint subnet must belong to the caller's VPC.")
		}
		if err = s.authorizeSubnetUse(ctx, action, subnet); err != nil {
			return nil, err
		}
		zone := str(subnet.Data.AvailabilityZoneId)
		if zone == "" {
			zone = str(subnet.Data.AvailabilityZone)
		}
		if zones[zone] {
			return nil, failure("InvalidParameterValue", "Interface endpoints support one subnet per availability zone.")
		}
		zones[zone] = true
		out = append(out, subnet)
	}
	return out, nil
}
func valueSet[S ~[]E, E ~string](ids S) api.ValueStringList {
	out := make(api.ValueStringList, len(ids))
	for i, id := range ids {
		out[i] = api.String(id)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
func endpointSetChange(current api.ValueStringList, add, remove []string) api.ValueStringList {
	set := map[string]bool{}
	for _, id := range current {
		set[string(id)] = true
	}
	for _, id := range remove {
		delete(set, id)
	}
	for _, id := range add {
		set[id] = true
	}
	out := make(api.ValueStringList, 0, len(set))
	for id := range set {
		out = append(out, api.String(id))
	}
	slices.Sort(out)
	return out
}
func endpointGroupSet(groups []SecurityGroupRecord) api.GroupIdentifierSet {
	out := make(api.GroupIdentifierSet, 0, len(groups))
	for _, g := range groups {
		out = append(out, api.SecurityGroupIdentifier{GroupId: copyPointer(g.Data.GroupId), GroupName: copyPointer(g.Data.GroupName)})
	}
	return out
}
func endpointGroupIDs(v api.GroupIdentifierSet) api.SecurityGroupIdStringList {
	out := make(api.SecurityGroupIdStringList, 0, len(v))
	for _, g := range v {
		out = append(out, api.SecurityGroupId(str(g.GroupId)))
	}
	return out
}

func (s *Service) createVPCEndpoint(ctx context.Context, tx Transaction, in *api.CreateVpcEndpointRequest) (*api.CreateVpcEndpointResult, error) {
	tags, err := CreationTags(in.TagSpecifications, "vpc-endpoint")
	if err != nil {
		return nil, err
	}
	vpcID := str(in.VpcId)
	vpc, err := tx.VPC(key(ctx, vpcID))
	if errors.Is(err, ErrNotFound) {
		return nil, missing("vpc", vpcID)
	}
	if err != nil {
		return nil, err
	}
	if err = s.authorizeCreateWith(ctx, "CreateVpcEndpoint", "vpc-endpoint", "*", tags, vpcConditions(scopeFor(ctx), vpcID)); err != nil {
		return nil, err
	}
	if err = s.authorizeWith(ctx, "CreateVpcEndpoint", "vpc", vpcID, vpc.Data.Tags, vpcConditions(scopeFor(ctx), vpcID)); err != nil {
		return nil, err
	}
	kind := str(in.VpcEndpointType)
	if kind == "" {
		kind = "Gateway"
	}
	if kind != "Gateway" && kind != "Interface" {
		return nil, unsupported("Only Gateway and Interface endpoints are supported.")
	}
	if in.ResourceConfigurationArn != nil || in.ServiceNetworkArn != nil {
		return nil, unsupported("Service-network and resource endpoints are not supported.")
	}
	if err = endpointService(scopeFor(ctx), str(in.ServiceName), kind, str(in.ServiceRegion)); err != nil {
		return nil, err
	}
	dns, err := endpointDNS(kind, in.PrivateDnsEnabled, in.DnsOptions, in.IpAddressType)
	if err != nil {
		return nil, err
	}
	policy, err := endpointPolicy(in.PolicyDocument)
	if err != nil {
		return nil, err
	}
	routes, subnets := valueSet(in.RouteTableIds), valueSet(in.SubnetIds)
	if kind == "Gateway" && (len(subnets) > 0 || len(in.SecurityGroupIds) > 0 || len(in.SubnetConfigurations) > 0) {
		return nil, failure("InvalidParameterCombination", "Gateway endpoints accept route tables, not subnets or security groups.")
	}
	if kind == "Interface" && len(routes) > 0 {
		return nil, failure("InvalidParameterCombination", "Interface endpoints do not accept route tables.")
	}
	if kind == "Interface" && len(subnets) == 0 {
		return nil, failure("MissingParameter", "At least one subnet is required for Interface endpoint controls.")
	}
	if _, err = s.validateEndpointRoutes(ctx, tx, "CreateVpcEndpoint", vpcID, routes); err != nil {
		return nil, err
	}
	subnetRecords, err := s.endpointSubnets(ctx, tx, "CreateVpcEndpoint", vpcID, subnets)
	if err != nil {
		return nil, err
	}
	var groups []SecurityGroupRecord
	if kind == "Interface" {
		groups, err = s.networkInterfaceGroups(ctx, tx, "CreateVpcEndpoint", api.SecurityGroupIdStringList(in.SecurityGroupIds), vpcID)
		if err != nil {
			return nil, err
		}
		for _, subnet := range subnetRecords {
			if err = validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
				return nil, err
			}
		}
		if boolValue(in.PrivateDnsEnabled) && (!vpc.DNSSupport || !vpc.DNSHostnames) {
			return nil, failure("InvalidParameterValue", "Private DNS requires VPC DNS support and hostnames.")
		}
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	admitted := CloneCreateVpcEndpointRequest(*in)
	admitted.ClientToken = nil
	admitted.DryRun = nil
	admitted.TagSpecifications = nil
	admitted.VpcEndpointType = new(api.VpcEndpointType(kind))
	admitted.ServiceRegion = new(api.String(scopeFor(ctx).Region))
	admitted.IpAddressType = new(api.IpAddressType("ipv4"))
	admitted.PrivateDnsEnabled = new(api.Boolean(boolValue(in.PrivateDnsEnabled)))
	admitted.PolicyDocument = copyPointer(policy)
	slices.Sort(admitted.RouteTableIds)
	admitted.RouteTableIds = slices.Compact(admitted.RouteTableIds)
	slices.Sort(admitted.SubnetIds)
	admitted.SubnetIds = slices.Compact(admitted.SubnetIds)
	slices.Sort(admitted.SecurityGroupIds)
	admitted.SecurityGroupIds = slices.Compact(admitted.SecurityGroupIds)
	fingerprint, err := networkOwnerFingerprint(admitted)
	if err != nil {
		return nil, err
	}
	token := str(in.ClientToken)
	previous, err := networkOwnerReplay(tx, scopeFor(ctx), "CreateVpcEndpoint", token, fingerprint)
	if err != nil {
		return nil, err
	}
	if previous != "" {
		v, err := tx.VPCEndpoint(key(ctx, previous))
		if err != nil {
			return nil, err
		}
		return &api.CreateVpcEndpointResult{ClientToken: copyPointer(in.ClientToken), VpcEndpoint: &v.Data}, nil
	}
	id, err := tx.NextID(scopeFor(ctx), "vpce")
	if err != nil {
		return nil, err
	}
	data := api.VpcEndpoint{VpcEndpointId: new(api.String(id)), VpcId: new(api.String(vpcID)), VpcEndpointType: new(api.VpcEndpointType(kind)), ServiceName: copyPointer(in.ServiceName), ServiceRegion: new(api.String(scopeFor(ctx).Region)), OwnerId: new(api.String(scopeFor(ctx).AccountID)), RequesterManaged: new(api.Boolean(false)), CreationTimestamp: new(s.clock.Now()), State: new(api.State("available")), Tags: tags, PolicyDocument: policy, PrivateDnsEnabled: new(api.Boolean(boolValue(in.PrivateDnsEnabled))), DnsOptions: dns, IpAddressType: new(api.IpAddressType("ipv4")), RouteTableIds: routes, SubnetIds: subnets, Groups: endpointGroupSet(groups), NetworkInterfaceIds: api.ValueStringList{}, DnsEntries: api.DnsEntrySet{}}
	v := VPCEndpointRecord{Key: key(ctx, id), Data: data}
	if kind == "Gateway" {
		if err = s.syncEndpointRoutes(ctx, tx, "CreateVpcEndpoint", &v, nil); err != nil {
			return nil, err
		}
	} else {
		configured, err := endpointSubnetConfiguration(in.SubnetConfigurations, subnets)
		if err != nil {
			return nil, err
		}
		for _, subnet := range subnetRecords {
			eni, err := createNetworkOwnerENI(ctx, tx, subnet, id, "vpc_endpoint", configured[subnet.Key.ID], groups)
			if err != nil {
				return nil, err
			}
			v.Data.NetworkInterfaceIds = append(v.Data.NetworkInterfaceIds, api.String(eni.Key.ID))
		}
	}
	if err = tx.PutVPCEndpoint(v); err != nil {
		return nil, err
	}
	if err = retainNetworkOwner(tx, scopeFor(ctx), "CreateVpcEndpoint", token, id, fingerprint); err != nil {
		return nil, err
	}
	return &api.CreateVpcEndpointResult{ClientToken: copyPointer(in.ClientToken), VpcEndpoint: &v.Data}, nil
}
func endpointSubnetConfiguration(configs api.SubnetConfigurationsList, subnets api.ValueStringList) (map[string]string, error) {
	out := map[string]string{}
	for _, c := range configs {
		id := str(c.SubnetId)
		if !slices.Contains(subnets, api.String(id)) {
			return nil, failure("InvalidParameterValue", "Subnet configuration must name an associated subnet.")
		}
		if _, ok := out[id]; ok {
			return nil, failure("InvalidParameterValue", "Duplicate subnet configuration.")
		}
		if c.Ipv6 != nil {
			return nil, unsupported("IPv6 endpoint interfaces are not supported.")
		}
		out[id] = str(c.Ipv4)
	}
	return out, nil
}
func (s *Service) syncEndpointRoutes(ctx context.Context, tx Transaction, action string, v *VPCEndpointRecord, old api.ValueStringList) error {
	tables, err := s.validateEndpointRoutes(ctx, tx, action, str(v.Data.VpcId), endpointSetChange(old, stringsOf(v.Data.RouteTableIds), nil))
	if err != nil {
		return err
	}
	prefix := endpointPrefixList(scopeFor(ctx), str(v.Data.ServiceName))
	for _, rt := range tables {
		routes := api.RouteList{}
		found := false
		for _, route := range rt.Data.Routes {
			if str(route.GatewayId) == v.Key.ID && str(route.DestinationPrefixListId) == prefix {
				continue
			}
			if slices.Contains(v.Data.RouteTableIds, api.String(rt.Key.ID)) && str(route.DestinationPrefixListId) == prefix {
				found = true
			}
			routes = append(routes, route)
		}
		if slices.Contains(v.Data.RouteTableIds, api.String(rt.Key.ID)) {
			if found {
				return failure("RouteAlreadyExists", "Route table already contains an endpoint route for this service.")
			}
			routes = append(routes, api.Route{DestinationPrefixListId: new(api.String(prefix)), GatewayId: new(api.String(v.Key.ID)), Origin: new(api.RouteOrigin("CreateRoute")), State: new(api.RouteState("active"))})
		}
		rt.Data.Routes = routes
		if err = tx.PutRouteTable(rt); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) modifyVPCEndpoint(ctx context.Context, tx Transaction, in *api.ModifyVpcEndpointRequest) (*api.ModifyVpcEndpointResult, error) {
	v, err := s.endpointForAction(ctx, tx, "ModifyVpcEndpoint", str(in.VpcEndpointId))
	if err != nil {
		return nil, err
	}
	if str(v.Data.State) != "available" {
		return nil, failure("InvalidState", "Endpoint is not available.")
	}
	oldRoutes := v.Data.RouteTableIds
	kind := str(v.Data.VpcEndpointType)
	v.Data.RouteTableIds = endpointSetChange(v.Data.RouteTableIds, stringsOf(in.AddRouteTableIds), stringsOf(in.RemoveRouteTableIds))
	newSubnets := endpointSetChange(v.Data.SubnetIds, stringsOf(in.AddSubnetIds), stringsOf(in.RemoveSubnetIds))
	if kind == "Gateway" && (len(in.AddSubnetIds) > 0 || len(in.RemoveSubnetIds) > 0 || len(in.AddSecurityGroupIds) > 0 || len(in.RemoveSecurityGroupIds) > 0 || len(in.SubnetConfigurations) > 0) {
		return nil, failure("InvalidParameterCombination", "Gateway endpoints cannot modify interfaces.")
	}
	if kind == "Interface" && (len(in.AddRouteTableIds) > 0 || len(in.RemoveRouteTableIds) > 0) {
		return nil, failure("InvalidParameterCombination", "Interface endpoints cannot modify route tables.")
	}
	if in.PolicyDocument != nil && boolValue(in.ResetPolicy) {
		return nil, failure("InvalidParameterCombination", "Specify PolicyDocument or ResetPolicy, not both.")
	}
	if boolValue(in.ResetPolicy) {
		v.Data.PolicyDocument = new(api.String(defaultEndpointPolicy))
	} else if in.PolicyDocument != nil {
		v.Data.PolicyDocument, err = endpointPolicy(in.PolicyDocument)
		if err != nil {
			return nil, err
		}
	}
	enabled := v.Data.PrivateDnsEnabled
	if in.PrivateDnsEnabled != nil {
		enabled = in.PrivateDnsEnabled
	}
	dns, err := endpointDNS(kind, enabled, in.DnsOptions, in.IpAddressType)
	if err != nil {
		return nil, err
	}
	v.Data.PrivateDnsEnabled = copyPointer(enabled)
	if in.DnsOptions != nil {
		v.Data.DnsOptions = dns
	}
	if boolValue(enabled) {
		vpc, err := tx.VPC(key(ctx, str(v.Data.VpcId)))
		if err != nil {
			return nil, err
		}
		if !vpc.DNSSupport || !vpc.DNSHostnames {
			return nil, failure("InvalidParameterValue", "Private DNS requires VPC DNS support and hostnames.")
		}
	}
	if _, err = s.validateEndpointRoutes(ctx, tx, "ModifyVpcEndpoint", str(v.Data.VpcId), v.Data.RouteTableIds); err != nil {
		return nil, err
	}
	subnets, err := s.endpointSubnets(ctx, tx, "ModifyVpcEndpoint", str(v.Data.VpcId), newSubnets)
	if err != nil {
		return nil, err
	}
	var groups []SecurityGroupRecord
	if kind == "Interface" {
		if len(newSubnets) == 0 {
			return nil, failure("InvalidParameterValue", "Interface endpoint requires at least one subnet.")
		}
		ids := endpointSetChange(valueSet(endpointGroupIDs(v.Data.Groups)), stringsOf(in.AddSecurityGroupIds), stringsOf(in.RemoveSecurityGroupIds))
		if len(ids) == 0 {
			return nil, failure("InvalidGroup.NotFound", "Interface endpoint requires at least one security group.")
		}
		groupIDs := api.SecurityGroupIdStringList{}
		for _, id := range ids {
			groupIDs = append(groupIDs, api.SecurityGroupId(id))
		}
		groups, err = s.networkInterfaceGroups(ctx, tx, "ModifyVpcEndpoint", groupIDs, str(v.Data.VpcId))
		if err != nil {
			return nil, err
		}
		for _, subnet := range subnets {
			if err = validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
				return nil, err
			}
		}
	}
	configs, err := endpointSubnetConfiguration(in.SubnetConfigurations, newSubnets)
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if kind == "Gateway" {
		if err = s.syncEndpointRoutes(ctx, tx, "ModifyVpcEndpoint", &v, oldRoutes); err != nil {
			return nil, err
		}
	} else {
		existing := map[string]NetworkInterfaceRecord{}
		for _, id := range v.Data.NetworkInterfaceIds {
			eni, err := tx.NetworkInterface(key(ctx, string(id)))
			if err != nil {
				return nil, err
			}
			if eni.NetworkControlOwnerID != v.Key.ID {
				return nil, failure("DependencyViolation", "Endpoint interface has a different owner.")
			}
			subnetID := str(eni.Data.SubnetId)
			if !slices.Contains(newSubnets, api.String(subnetID)) {
				if err = deleteNetworkOwnerENI(ctx, tx, eni.Key.ID, v.Key.ID); err != nil {
					return nil, err
				}
			} else {
				existing[subnetID] = eni
			}
		}
		v.Data.NetworkInterfaceIds = api.ValueStringList{}
		for _, subnet := range subnets {
			eni, ok := existing[subnet.Key.ID]
			if ok {
				if ip := configs[subnet.Key.ID]; ip != "" && ip != str(eni.Data.PrivateIpAddress) {
					if err = deleteNetworkOwnerENI(ctx, tx, eni.Key.ID, v.Key.ID); err != nil {
						return nil, err
					}
					ok = false
				}
			}
			if !ok {
				eni, err = createNetworkOwnerENI(ctx, tx, subnet, v.Key.ID, "vpc_endpoint", configs[subnet.Key.ID], groups)
				if err != nil {
					return nil, err
				}
			} else {
				eni.Data.Groups = networkInterfaceGroupIdentifiers(groups)
				if err = tx.PutNetworkInterface(eni); err != nil {
					return nil, err
				}
			}
			v.Data.NetworkInterfaceIds = append(v.Data.NetworkInterfaceIds, api.String(eni.Key.ID))
		}
		v.Data.SubnetIds = newSubnets
		v.Data.Groups = endpointGroupSet(groups)
	}
	if err = tx.PutVPCEndpoint(v); err != nil {
		return nil, err
	}
	return &api.ModifyVpcEndpointResult{Return: new(api.Boolean(true))}, nil
}
func (s *Service) deleteVPCEndpoints(ctx context.Context, tx Transaction, in *api.DeleteVpcEndpointsRequest) (*api.DeleteVpcEndpointsResult, error) {
	if len(in.VpcEndpointIds) == 0 {
		return nil, failure("MissingParameter", "VpcEndpointIds are required.")
	}
	rows := make([]VPCEndpointRecord, 0, len(in.VpcEndpointIds))
	for _, id := range valueSet(in.VpcEndpointIds) {
		v, err := s.endpointForAction(ctx, tx, "DeleteVpcEndpoints", string(id))
		if err != nil {
			return nil, err
		}
		rows = append(rows, v)
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	for _, v := range rows {
		if str(v.Data.State) == "deleted" {
			continue
		}
		if str(v.Data.VpcEndpointType) == "Gateway" {
			old := v.Data.RouteTableIds
			v.Data.RouteTableIds = api.ValueStringList{}
			if err := s.syncEndpointRoutes(ctx, tx, "DeleteVpcEndpoints", &v, old); err != nil {
				return nil, err
			}
		} else {
			for _, id := range v.Data.NetworkInterfaceIds {
				if err := deleteNetworkOwnerENI(ctx, tx, string(id), v.Key.ID); err != nil {
					return nil, err
				}
			}
			v.Data.NetworkInterfaceIds = api.ValueStringList{}
			v.Data.SubnetIds = api.ValueStringList{}
		}
		v.Data.State = new(api.State("deleted"))
		if err := tx.PutVPCEndpoint(v); err != nil {
			return nil, err
		}
	}
	return &api.DeleteVpcEndpointsResult{Unsuccessful: api.UnsuccessfulItemSet{}}, nil
}
func (s *Service) describeVPCEndpoints(ctx context.Context, tx Transaction, in *api.DescribeVpcEndpointsRequest) (*api.DescribeVpcEndpointsResult, error) {
	if err := s.authorize(ctx, "DescribeVpcEndpoints", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	rows, err := tx.VPCEndpoints(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := []pageItem{}
	data := map[string]api.VpcEndpoint{}
	for _, v := range rows {
		d := v.Data
		items = append(items, pageItem{ID: v.Key.ID, Tags: d.Tags, Fields: map[string][]string{"vpc-endpoint-id": {v.Key.ID}, "vpc-id": {str(d.VpcId)}, "service-name": {str(d.ServiceName)}, "vpc-endpoint-type": {str(d.VpcEndpointType)}, "state": {str(d.State)}, "subnet-id": stringsOf(d.SubnetIds), "route-table-id": stringsOf(d.RouteTableIds), "group-id": stringsOf(endpointGroupIDs(d.Groups)), "owner-id": {str(d.OwnerId)}}})
		data[v.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeVpcEndpoints", stringsOf(in.VpcEndpointIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeVpcEndpointsResult{VpcEndpoints: api.VpcEndpointSet{}, NextToken: next}
	for _, id := range ids {
		out.VpcEndpoints = append(out.VpcEndpoints, data[id])
	}
	return out, nil
}
