package ec2

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

// Native route dry runs authorize the route table before checking destinations,
// targets or even whether the table exists.
func (s *Service) authorizeRouteMutation(ctx context.Context, tx Reader, action, id string, dry *api.Boolean) (RouteTableRecord, error) {
	table, err := tx.RouteTable(key(ctx, id))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return table, err
	}
	if err := s.authorize(ctx, action, "route-table", id, table.Data.Tags); err != nil {
		return table, err
	}
	if err := dryRun(dry); err != nil {
		return table, err
	}
	return table, nil
}

func routeDestination(ipv4, ipv6 *api.String, prefixList *api.PrefixListResourceId) (api.Route, error) {
	count := 0
	for _, present := range []bool{ipv4 != nil, ipv6 != nil, prefixList != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		code := "InvalidParameterCombination"
		if count == 0 {
			code = "MissingParameter"
		}
		return api.Route{}, failure(code, "The request must contain exactly one of: destinationCidrBlock, destinationIpv6CidrBlock, destinationPrefixListId")
	}
	if prefixList != nil {
		// TODO: Comeback resolve and validate managed prefix lists before accepting routes.
		return api.Route{}, unsupported("Prefix-list route destinations are not implemented.")
	}
	raw, parameter := str(ipv4), "destinationCidrBlock"
	if ipv6 != nil {
		raw, parameter = str(ipv6), "destinationIpv6CidrBlock"
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Addr().Is4() != (ipv4 != nil) || prefix.Addr().Is4In6() {
		return api.Route{}, failure("InvalidParameterValue", fmt.Sprintf("Value (%s) for parameter %s is invalid. This is not a valid CIDR block.", raw, parameter))
	}
	route := api.Route{}
	if ipv4 != nil {
		route.DestinationCidrBlock = new(api.String(prefix.Masked().String()))
	} else {
		route.DestinationIpv6CidrBlock = new(api.String(prefix.Masked().String()))
	}
	return route, nil
}

func routeCIDR(route api.Route) string {
	if route.DestinationIpv6CidrBlock != nil {
		return str(route.DestinationIpv6CidrBlock)
	}
	return str(route.DestinationCidrBlock)
}

func routeIndex(table RouteTableRecord, destination api.Route) int {
	for index, route := range table.Data.Routes {
		if str(route.DestinationCidrBlock) == str(destination.DestinationCidrBlock) && str(route.DestinationIpv6CidrBlock) == str(destination.DestinationIpv6CidrBlock) && str(route.DestinationPrefixListId) == str(destination.DestinationPrefixListId) {
			return index
		}
	}
	return -1
}

func routeLocalDestination(table RouteTableRecord, destination api.Route) (equal, contained bool) {
	prefix, err := netip.ParsePrefix(routeCIDR(destination))
	if err != nil {
		return false, false
	}
	for _, route := range table.Data.Routes {
		if str(route.Origin) != string(api.RouteOriginCreateRouteTable) {
			continue
		}
		local, err := netip.ParsePrefix(routeCIDR(route))
		if err == nil && local.Addr().BitLen() == prefix.Addr().BitLen() && local.Bits() <= prefix.Bits() && local.Contains(prefix.Addr()) {
			contained = true
			if local == prefix {
				equal = true
			}
		}
	}
	return equal, contained
}

func routeTargetCount(req *api.CreateRouteRequest, local bool) int {
	count := 0
	for _, present := range []bool{req.GatewayId != nil, req.CarrierGatewayId != nil, req.CoreNetworkArn != nil, req.EgressOnlyInternetGatewayId != nil, req.InstanceId != nil, req.LocalGatewayId != nil, req.NatGatewayId != nil, req.NetworkInterfaceId != nil, req.OdbNetworkArn != nil, req.TransitGatewayId != nil, req.VpcEndpointId != nil, req.VpcPeeringConnectionId != nil, local} {
		if present {
			count++
		}
	}
	return count
}

func (s *Service) createRoute(ctx context.Context, tx Transaction, req *api.CreateRouteRequest) (*api.CreateRouteResult, error) {
	if err := s.changeRoute(ctx, tx, req, false, false); err != nil {
		return nil, err
	}
	return &api.CreateRouteResult{Return: new(api.Boolean(true))}, nil
}

func (s *Service) replaceRoute(ctx context.Context, tx Transaction, req *api.ReplaceRouteRequest) (*emptyResult, error) {
	input := api.CreateRouteRequest{
		RouteTableId: req.RouteTableId, DryRun: req.DryRun,
		DestinationCidrBlock: req.DestinationCidrBlock, DestinationIpv6CidrBlock: req.DestinationIpv6CidrBlock, DestinationPrefixListId: req.DestinationPrefixListId,
		GatewayId: req.GatewayId, CarrierGatewayId: req.CarrierGatewayId, CoreNetworkArn: req.CoreNetworkArn,
		EgressOnlyInternetGatewayId: req.EgressOnlyInternetGatewayId, InstanceId: req.InstanceId, LocalGatewayId: req.LocalGatewayId,
		NatGatewayId: req.NatGatewayId, NetworkInterfaceId: req.NetworkInterfaceId, OdbNetworkArn: req.OdbNetworkArn,
		TransitGatewayId: req.TransitGatewayId, VpcEndpointId: req.VpcEndpointId, VpcPeeringConnectionId: req.VpcPeeringConnectionId,
	}
	if err := s.changeRoute(ctx, tx, &input, true, boolValue(req.LocalTarget)); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) changeRoute(ctx context.Context, tx Transaction, req *api.CreateRouteRequest, replace, localTarget bool) error {
	action := "CreateRoute"
	if replace {
		action = "ReplaceRoute"
	}
	table, err := s.authorizeRouteMutation(ctx, tx, action, str(req.RouteTableId), req.DryRun)
	if err != nil {
		return err
	}
	destination, err := routeDestination(req.DestinationCidrBlock, req.DestinationIpv6CidrBlock, req.DestinationPrefixListId)
	if err != nil {
		return err
	}
	count := routeTargetCount(req, localTarget)
	if count != 1 {
		message := "The request must contain exactly one of gatewayId, localGatewayId, carrierGatewayId, natGatewayId, networkInterfaceId, vpcPeeringConnectionId, egressOnlyInternetGatewayId, transitGatewayId, vpcEndpointId, coreNetworkArn or instanceId"
		if replace {
			message += ", or must have localTarget set to true"
		}
		code := "InvalidParameterCombination"
		if count == 0 {
			code = "MissingParameter"
		}
		return failure(code, message)
	}
	if table.Key.ID == "" {
		return missing("route-table", str(req.RouteTableId))
	}
	equalLocal, insideLocal := routeLocalDestination(table, destination)
	gatewayID := str(req.GatewayId)
	if localTarget {
		if !equalLocal {
			return failure("InvalidParameterValue", "local-target only allowed with network local destination CIDRs")
		}
		gatewayID = "local"
	} else if req.NatGatewayId != nil {
		nat, err := tx.NatGateway(key(ctx, str(req.NatGatewayId)))
		if errors.Is(err, ErrNotFound) {
			return failure("NatGatewayNotFound", "The NAT gateway does not exist.")
		}
		if err != nil {
			return err
		}
		if str(nat.Data.VpcId) != str(table.Data.VpcId) {
			return failure("InvalidParameterValue", "Route table and NAT gateway belong to different networks.")
		}
		if str(nat.Data.State) != "available" {
			return failure("InvalidParameterValue", "The NAT gateway is not available.")
		}
		if destination.DestinationIpv6CidrBlock != nil {
			return unsupported("NAT64 route execution is not implemented.")
		}
		if insideLocal {
			return failure("InvalidParameterValue", "A NAT gateway cannot target a VPC-local destination.")
		}
	} else {
		if req.GatewayId == nil {
			return unsupported("This route target resource family is not implemented.")
		}
		if strings.HasPrefix(gatewayID, "vgw-") {
			return unsupported("Virtual private gateway route targets are not implemented.")
		}
		gateway, err := tx.InternetGateway(key(ctx, gatewayID))
		if errors.Is(err, ErrNotFound) {
			return failure("InvalidGatewayID.NotFound", fmt.Sprintf("The gateway ID '%s' does not exist", gatewayID))
		}
		if err != nil {
			return err
		}
		attached := false
		for _, attachment := range gateway.Data.Attachments {
			if str(attachment.VpcId) == str(table.Data.VpcId) {
				attached = true
			}
		}
		if !attached {
			return failure("InvalidParameterValue", fmt.Sprintf("route table %s and network gateway %s belong to different networks", table.Key.ID, gatewayID))
		}
		if insideLocal {
			return failure("InvalidParameterValue", fmt.Sprintf("The destination CIDR block %s is equal to or more specific than one of this VPC's CIDR blocks. This route can target only an interface or an instance.", routeCIDR(destination)))
		}
	}
	// Validate the target before checking duplicate destinations. Repeating a
	// CreateRoute for the same valid target succeeds; changing it requires ReplaceRoute.
	index := routeIndex(table, destination)
	if replace && index < 0 {
		return failure("InvalidParameterValue", fmt.Sprintf("There is no route defined for '%s' in the route table. Use CreateRoute instead.", routeCIDR(destination)))
	}
	if !replace && index >= 0 {
		if str(table.Data.Routes[index].GatewayId) == gatewayID && str(table.Data.Routes[index].NatGatewayId) == str(req.NatGatewayId) {
			return nil
		}
		return failure("RouteAlreadyExists", fmt.Sprintf("The route identified by %s already exists.", routeCIDR(destination)))
	}
	if req.NatGatewayId != nil {
		destination.NatGatewayId = new(api.String(str(req.NatGatewayId)))
	} else {
		destination.GatewayId = new(api.String(gatewayID))
	}
	destination.State = new(api.RouteStateActive)
	destination.Origin = new(api.RouteOriginCreateRoute)
	if localTarget {
		destination.Origin = new(api.RouteOriginCreateRouteTable)
	}
	slot := table.Key.ID + "|" + routeCIDR(destination)
	if err := relationAdmission(ctx, tx, "Route", slot, slot); err != nil {
		return err
	}
	if index >= 0 {
		table.Data.Routes[index] = destination
	} else {
		table.Data.Routes = append(table.Data.Routes, destination)
	}
	return tx.PutRouteTable(table)
}

func (s *Service) deleteRoute(ctx context.Context, tx Transaction, req *api.DeleteRouteRequest) (*emptyResult, error) {
	table, err := s.authorizeRouteMutation(ctx, tx, "DeleteRoute", str(req.RouteTableId), req.DryRun)
	if err != nil {
		return nil, err
	}
	destination, err := routeDestination(req.DestinationCidrBlock, req.DestinationIpv6CidrBlock, req.DestinationPrefixListId)
	if err != nil {
		return nil, err
	}
	index := routeIndex(table, destination)
	if index < 0 {
		parameter := "destination-cidr-block"
		if destination.DestinationIpv6CidrBlock != nil {
			parameter = "destination-ipv6-cidr-block"
		}
		return nil, failure("InvalidRoute.NotFound", fmt.Sprintf("no route with %s %s in route table %s", parameter, routeCIDR(destination), str(req.RouteTableId)))
	}
	if str(table.Data.Routes[index].Origin) == string(api.RouteOriginCreateRouteTable) {
		return nil, failure("InvalidParameterValue", fmt.Sprintf("cannot remove local route %s in route table %s", routeCIDR(destination), table.Key.ID))
	}
	slot := table.Key.ID + "|" + routeCIDR(destination)
	if err := relationAdmission(ctx, tx, "Route", slot, ""); err != nil {
		return nil, err
	}
	table.Data.Routes = append(table.Data.Routes[:index], table.Data.Routes[index+1:]...)
	if err := tx.PutRouteTable(table); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
