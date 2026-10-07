package ec2

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/ec2"
)

func (s *Service) natGatewayForAction(ctx context.Context, tx Reader, action, id string) (NatGatewayRecord, error) {
	v, err := tx.NatGateway(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return v, networkOwnerMissing("natgateway", id)
	}
	if err != nil {
		return v, err
	}
	return v, s.authorizeWith(ctx, action, "natgateway", id, v.Data.Tags, vpcConditions(scopeFor(ctx), str(v.Data.VpcId)))
}
func (s *Service) createNatGateway(ctx context.Context, tx Transaction, in *api.CreateNatGatewayRequest) (*api.CreateNatGatewayResult, error) {
	tags, err := CreationTags(in.TagSpecifications, "natgateway")
	if err != nil {
		return nil, err
	}
	subnet, err := s.subnetForUse(ctx, tx, str(in.SubnetId), "CreateNatGateway")
	if err != nil {
		return nil, err
	}
	if subnet.Key.ID == "" {
		return nil, missing("subnet", str(in.SubnetId))
	}
	if subnet.Key.Scope != scopeFor(ctx) {
		return nil, failure("InvalidParameterValue", "NAT gateway subnet must belong to the caller.")
	}
	if err = s.authorizeCreateWith(ctx, "CreateNatGateway", "natgateway", "*", tags, vpcConditions(scopeFor(ctx), str(subnet.Data.VpcId))); err != nil {
		return nil, err
	}
	if err = s.authorizeSubnetUse(ctx, "CreateNatGateway", subnet); err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.AvailabilityMode != nil && str(in.AvailabilityMode) != "zonal" || len(in.AvailabilityZoneAddresses) > 0 || in.VpcId != nil {
		return nil, unsupported("Only subnet-scoped zonal NAT gateways are supported.")
	}
	connectivity := str(in.ConnectivityType)
	if connectivity == "" {
		connectivity = "public"
	}
	if connectivity != "public" && connectivity != "private" {
		return nil, failure("InvalidParameterValue", "ConnectivityType must be public or private.")
	}
	if connectivity == "public" && str(in.AllocationId) == "" {
		return nil, failure("MissingParameter", "AllocationId is required for public NAT gateways.")
	}
	if connectivity == "private" && (in.AllocationId != nil || len(in.SecondaryAllocationIds) > 0) {
		return nil, failure("InvalidParameterCombination", "Private NAT gateways cannot bind Elastic IP addresses.")
	}
	admitted := CloneCreateNatGatewayRequest(*in)
	admitted.ClientToken = nil
	admitted.DryRun = nil
	admitted.TagSpecifications = nil
	admitted.ConnectivityType = new(api.ConnectivityType(connectivity))
	admitted.AvailabilityMode = new(api.AvailabilityMode("zonal"))
	if in.SecondaryPrivateIpAddressCount != nil && *in.SecondaryPrivateIpAddressCount <= 0 {
		return nil, failure("InvalidParameterValue", "SecondaryPrivateIpAddressCount must be positive.")
	}
	fingerprint, err := networkOwnerFingerprint(admitted)
	if err != nil {
		return nil, err
	}
	token := str(in.ClientToken)
	previous, err := networkOwnerReplay(tx, scopeFor(ctx), "CreateNatGateway", token, fingerprint)
	if err != nil {
		return nil, err
	}
	if previous != "" {
		v, err := tx.NatGateway(key(ctx, previous))
		if err != nil {
			return nil, err
		}
		return &api.CreateNatGatewayResult{ClientToken: copyPointer(in.ClientToken), NatGateway: &v.Data}, nil
	}
	id, err := tx.NextID(scopeFor(ctx), "nat")
	if err != nil {
		return nil, err
	}
	eni, err := createNetworkOwnerENI(ctx, tx, subnet, id, "nat_gateway", str(in.PrivateIpAddress), nil)
	if err != nil {
		return nil, err
	}
	v := NatGatewayRecord{Key: key(ctx, id), Data: api.NatGateway{NatGatewayId: new(api.String(id)), VpcId: copyPointer(subnet.Data.VpcId), SubnetId: copyPointer(subnet.Data.SubnetId), ConnectivityType: new(api.ConnectivityType(connectivity)), AvailabilityMode: new(api.AvailabilityMode("zonal")), CreateTime: new(s.clock.Now()), State: new(api.NatGatewayState("available")), Tags: tags}}
	first := api.NatGatewayAddress{NetworkInterfaceId: new(api.String(eni.Key.ID)), PrivateIp: copyPointer(eni.Data.PrivateIpAddress), IsPrimary: new(api.Boolean(true)), Status: new(api.NatGatewayAddressStatus("succeeded"))}
	if connectivity == "public" {
		if err = s.bindNatEIP(ctx, tx, "CreateNatGateway", &first, str(in.AllocationId)); err != nil {
			return nil, err
		}
	}
	v.Data.NatGatewayAddresses = api.NatGatewayAddressList{first}
	if len(in.SecondaryAllocationIds) > 0 || len(in.SecondaryPrivateIpAddresses) > 0 || in.SecondaryPrivateIpAddressCount != nil {
		count := 0
		if in.SecondaryPrivateIpAddressCount != nil {
			count = int(*in.SecondaryPrivateIpAddressCount)
		}
		if err = s.addNatAddresses(ctx, tx, "CreateNatGateway", &v, stringsOf(in.SecondaryAllocationIds), stringsOf(in.SecondaryPrivateIpAddresses), count); err != nil {
			return nil, err
		}
	}
	if err = tx.PutNatGateway(v); err != nil {
		return nil, err
	}
	if err = retainNetworkOwner(tx, scopeFor(ctx), "CreateNatGateway", token, id, fingerprint); err != nil {
		return nil, err
	}
	return &api.CreateNatGatewayResult{ClientToken: copyPointer(in.ClientToken), NatGateway: &v.Data}, nil
}
func (s *Service) bindNatEIP(ctx context.Context, tx Transaction, action string, address *api.NatGatewayAddress, allocation string) error {
	eip, err := loadPublicAddress(ctx, tx, allocation, "")
	if err != nil {
		return err
	}
	if err = s.authorizeWith(ctx, action, "elastic-ip", allocation, eip.Data.Tags, addressConditions(eip.Data)); err != nil {
		return err
	}
	if eip.Automatic || str(eip.Data.Domain) != "vpc" || str(eip.Data.NetworkBorderGroup) != scopeFor(ctx).Region {
		return failure("InvalidParameterValue", "NAT Elastic IP must be a VPC address in the same region.")
	}
	if eip.Data.AssociationId != nil {
		return failure("Resource.AlreadyAssociated", "Elastic IP is already attached.")
	}
	association, err := tx.NextID(scopeFor(ctx), "eipassoc")
	if err != nil {
		return err
	}
	eip.Data.AssociationId = new(api.String(association))
	eip.Data.NetworkInterfaceId = copyPointer(address.NetworkInterfaceId)
	eip.Data.PrivateIpAddress = copyPointer(address.PrivateIp)
	address.AllocationId = new(api.String(allocation))
	address.AssociationId = new(api.String(association))
	address.PublicIp = copyPointer(eip.Data.PublicIp)
	return tx.PutPublicAddress(eip)
}
func (s *Service) addNatAddresses(ctx context.Context, tx Transaction, action string, v *NatGatewayRecord, allocations, ips []string, count int) error {
	if count < 0 || count > 7 {
		return failure("InvalidParameterValue", "Secondary private address count must be between 0 and 7.")
	}
	public := str(v.Data.ConnectivityType) == "public"
	if public {
		if count != 0 || len(ips) > 0 && len(ips) != len(allocations) {
			return failure("InvalidParameterCombination", "Public NAT secondary private addresses must match allocations.")
		}
		count = len(allocations)
	} else {
		if len(allocations) > 0 {
			return failure("InvalidParameterCombination", "Private NAT cannot bind Elastic IPs.")
		}
		if count > 0 && len(ips) > 0 {
			return failure("InvalidParameterCombination", "Specify addresses or count, not both.")
		}
		if len(ips) > 0 {
			count = len(ips)
		}
	}
	if count == 0 {
		return failure("MissingParameter", "At least one secondary address is required.")
	}
	limit := 8
	if public {
		limit = 2
	}
	if len(v.Data.NatGatewayAddresses)+count > limit {
		return failure("NatGatewayLimitExceeded", "Too many NAT gateway addresses.")
	}
	eni, err := tx.NetworkInterface(key(ctx, str(v.Data.NatGatewayAddresses[0].NetworkInterfaceId)))
	if err != nil {
		return err
	}
	subnet, err := tx.Subnet(interfaceSubnetKey(eni))
	if err != nil {
		return err
	}
	pool, err := networkInterfaceAddressPool(ctx, tx, subnet)
	if err != nil {
		return err
	}
	for i := range count {
		ip := ""
		if i < len(ips) {
			ip = ips[i]
			err = pool.reserveExplicit(ip, false)
		} else {
			ip, err = pool.allocate()
		}
		if err != nil {
			return err
		}
		address := api.NatGatewayAddress{NetworkInterfaceId: new(api.String(eni.Key.ID)), PrivateIp: new(api.String(ip)), IsPrimary: new(api.Boolean(false)), Status: new(api.NatGatewayAddressStatus("succeeded"))}
		if public {
			if err = s.bindNatEIP(ctx, tx, action, &address, allocations[i]); err != nil {
				return err
			}
		}
		eni.Data.PrivateIpAddresses = append(eni.Data.PrivateIpAddresses, newNetworkInterfaceAddress(ip, false))
		v.Data.NatGatewayAddresses = append(v.Data.NatGatewayAddresses, address)
	}
	if err = changeNetworkInterfaceCapacity(tx, subnet, -count); err != nil {
		return err
	}
	return tx.PutNetworkInterface(eni)
}
func (s *Service) removeNatAddresses(ctx context.Context, tx Transaction, v *NatGatewayRecord, selected map[string]bool, byAssociation bool) error {
	eni, err := tx.NetworkInterface(key(ctx, str(v.Data.NatGatewayAddresses[0].NetworkInterfaceId)))
	if err != nil {
		return err
	}
	removed := map[string]bool{}
	kept := api.NatGatewayAddressList{}
	for _, a := range v.Data.NatGatewayAddresses {
		selector := str(a.PrivateIp)
		if byAssociation {
			selector = str(a.AssociationId)
		}
		if !selected[selector] {
			kept = append(kept, a)
			continue
		}
		delete(selected, selector)
		if boolValue(a.IsPrimary) {
			return failure("InvalidParameterValue", "The primary NAT gateway address cannot be removed.")
		}
		if a.AllocationId != nil {
			eip, err := tx.PublicAddress(key(ctx, str(a.AllocationId)))
			if err != nil {
				return err
			}
			if str(eip.Data.AssociationId) != str(a.AssociationId) {
				return failure("DependencyViolation", "Elastic IP attachment no longer belongs to NAT gateway.")
			}
			clearAddressAssociation(&eip)
			if err = tx.PutPublicAddress(eip); err != nil {
				return err
			}
		}
		removed[str(a.PrivateIp)] = true
	}
	if len(selected) > 0 {
		return failure("InvalidParameterValue", "Address does not belong to NAT gateway.")
	}
	private := api.NetworkInterfacePrivateIpAddressList{}
	for _, a := range eni.Data.PrivateIpAddresses {
		if !removed[str(a.PrivateIpAddress)] {
			private = append(private, a)
		}
	}
	eni.Data.PrivateIpAddresses = private
	subnet, err := tx.Subnet(interfaceSubnetKey(eni))
	if err != nil {
		return err
	}
	if err = changeNetworkInterfaceCapacity(tx, subnet, len(removed)); err != nil {
		return err
	}
	if err = tx.PutNetworkInterface(eni); err != nil {
		return err
	}
	v.Data.NatGatewayAddresses = kept
	return tx.PutNatGateway(*v)
}
func (s *Service) deleteNatGateway(ctx context.Context, tx Transaction, in *api.DeleteNatGatewayRequest) (*api.DeleteNatGatewayResult, error) {
	v, err := s.natGatewayForAction(ctx, tx, "DeleteNatGateway", str(in.NatGatewayId))
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(v.Data.State) == "deleted" {
		return &api.DeleteNatGatewayResult{NatGatewayId: copyPointer(v.Data.NatGatewayId)}, nil
	}
	routes, err := tx.RouteTables(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, rt := range routes {
		changed := false
		for i := range rt.Data.Routes {
			if str(rt.Data.Routes[i].NatGatewayId) == v.Key.ID {
				rt.Data.Routes[i].State = new(api.RouteState("blackhole"))
				changed = true
			}
		}
		if changed {
			if err = tx.PutRouteTable(rt); err != nil {
				return nil, err
			}
		}
	}
	for _, a := range v.Data.NatGatewayAddresses {
		if a.AllocationId != nil {
			eip, err := tx.PublicAddress(key(ctx, str(a.AllocationId)))
			if err != nil {
				return nil, err
			}
			if str(eip.Data.AssociationId) != str(a.AssociationId) {
				return nil, failure("DependencyViolation", "Elastic IP attachment has a different owner.")
			}
			clearAddressAssociation(&eip)
			if err = tx.PutPublicAddress(eip); err != nil {
				return nil, err
			}
		}
	}
	if err = deleteNetworkOwnerENI(ctx, tx, str(v.Data.NatGatewayAddresses[0].NetworkInterfaceId), v.Key.ID); err != nil {
		return nil, err
	}
	v.Data.State = new(api.NatGatewayState("deleted"))
	v.Data.DeleteTime = new(s.clock.Now())
	if err = tx.PutNatGateway(v); err != nil {
		return nil, err
	}
	return &api.DeleteNatGatewayResult{NatGatewayId: copyPointer(v.Data.NatGatewayId)}, nil
}
func (s *Service) describeNatGateways(ctx context.Context, tx Transaction, in *api.DescribeNatGatewaysRequest) (*api.DescribeNatGatewaysResult, error) {
	if err := s.authorize(ctx, "DescribeNatGateways", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	rows, err := tx.NatGateways(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := []pageItem{}
	data := map[string]api.NatGateway{}
	for _, v := range rows {
		d := v.Data
		fields := map[string][]string{"nat-gateway-id": {v.Key.ID}, "subnet-id": {str(d.SubnetId)}, "vpc-id": {str(d.VpcId)}, "state": {str(d.State)}, "connectivity-type": {str(d.ConnectivityType)}}
		for _, a := range d.NatGatewayAddresses {
			fields["nat-gateway-address.allocation-id"] = append(fields["nat-gateway-address.allocation-id"], str(a.AllocationId))
			fields["nat-gateway-address.private-ip"] = append(fields["nat-gateway-address.private-ip"], str(a.PrivateIp))
			fields["nat-gateway-address.public-ip"] = append(fields["nat-gateway-address.public-ip"], str(a.PublicIp))
		}
		items = append(items, pageItem{ID: v.Key.ID, Tags: d.Tags, Fields: fields})
		data[v.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeNatGateways", stringsOf(in.NatGatewayIds), in.Filter, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeNatGatewaysResult{NatGateways: api.NatGatewayList{}, NextToken: next}
	for _, id := range ids {
		out.NatGateways = append(out.NatGateways, data[id])
	}
	return out, nil
}
