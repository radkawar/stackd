package ec2

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"stackd/compute/network"
)

func lambdaFunctionRouteTable(tx Reader, subnet SubnetRecord) (*RouteTableRecord, error) {
	tables, err := tx.RouteTables(subnet.Key.Scope)
	if err != nil {
		return nil, err
	}
	var selected, main *RouteTableRecord
	for i := range tables {
		table := &tables[i]
		if str(table.Data.VpcId) != str(subnet.Data.VpcId) {
			continue
		}
		for _, association := range table.Data.Associations {
			if association.AssociationState != nil && str(association.AssociationState.State) != "associated" {
				continue
			}
			if str(association.SubnetId) == subnet.Key.ID {
				selected = table
			}
			if boolValue(association.Main) {
				main = table
			}
		}
	}
	if selected == nil {
		selected = main
	}
	return selected, nil
}

func lambdaFunctionNetworkSpecification(ctx context.Context, tx Reader, eni NetworkInterfaceRecord) (network.Specification, error) {
	out, err := networkSpecification(ctx, tx, eni)
	if err != nil {
		return out, err
	}
	subnet, err := interfaceSubnet(tx, eni)
	if err != nil {
		return out, err
	}
	table, err := lambdaFunctionRouteTable(tx, subnet)
	if err != nil {
		return out, err
	}
	if table == nil {
		return out, unsupported("Lambda native VPC routing requires an authoritative subnet route table.")
	}
	if table != nil {
		for _, route := range table.Data.Routes {
			if route.DestinationCidrBlock == nil {
				continue
			}
			destination, err := netip.ParsePrefix(str(route.DestinationCidrBlock))
			if err != nil || !destination.Addr().Is4() {
				return out, unsupported("Lambda native NAT requires IPv4 routes.")
			}
			local := str(route.State) == "active" && str(route.GatewayId) == "local"
			out.Policy.PrivateRoutes = append(out.Policy.PrivateRoutes, network.PrivateRoute{Destination: destination, Local: local})
			if str(route.GatewayId) == "local" {
				continue
			}
			rule := network.NATRoute{Destination: destination, GatewayID: str(route.NatGatewayId)}
			if str(route.State) == "active" && rule.GatewayID != "" {
				nat, err := tx.NatGateway(ResourceKey{Scope: subnet.Key.Scope, ID: rule.GatewayID})
				if err != nil && !errors.Is(err, ErrNotFound) {
					return out, err
				}
				if err == nil && str(nat.Data.State) == "available" && str(nat.Data.VpcId) == str(subnet.Data.VpcId) && str(nat.Data.ConnectivityType) == "public" {
					natSubnet, err := tx.Subnet(ResourceKey{Scope: subnet.Key.Scope, ID: str(nat.Data.SubnetId)})
					if err != nil {
						return out, err
					}
					internet, err := taskInternetRoute(ctx, tx, natSubnet)
					if err != nil {
						return out, err
					}
					if internet {
						for _, address := range nat.Data.NatGatewayAddresses {
							if !boolValue(address.IsPrimary) || str(address.Status) != "succeeded" || address.AllocationId == nil {
								continue
							}
							eip, err := tx.PublicAddress(ResourceKey{Scope: subnet.Key.Scope, ID: str(address.AllocationId)})
							if err != nil {
								return out, err
							}
							if str(eip.Data.AssociationId) != str(address.AssociationId) || str(eip.Data.NetworkInterfaceId) != str(address.NetworkInterfaceId) || str(eip.Data.PublicIp) != str(address.PublicIp) {
								continue
							}
							reservation, err := tx.NetworkInterface(ResourceKey{Scope: subnet.Key.Scope, ID: str(address.NetworkInterfaceId)})
							if err != nil {
								return out, err
							}
							if reservation.NetworkControlOwnerID != nat.Key.ID || str(reservation.Data.PrivateIpAddress) != str(address.PrivateIp) || !boolValue(reservation.Data.RequesterManaged) {
								continue
							}
							natSpec, err := networkSpecification(ctx, tx, reservation)
							if err != nil {
								return out, err
							}
							rule.Allowed, rule.Ingress, rule.Egress = true, natSpec.Policy.ACLIngress, natSpec.Policy.ACLEgress
							break
						}
					}
				}
			}
			out.Policy.NATRoutes = append(out.Policy.NATRoutes, rule)
		}
		slices.SortFunc(out.Policy.NATRoutes, func(a, b network.NATRoute) int { return b.Destination.Bits() - a.Destination.Bits() })
		slices.SortFunc(out.Policy.PrivateRoutes, func(a, b network.PrivateRoute) int { return b.Destination.Bits() - a.Destination.Bits() })
	}
	endpoints, err := tx.VPCEndpoints(subnet.Key.Scope)
	if err != nil {
		return out, err
	}
	for _, endpoint := range endpoints {
		if str(endpoint.Data.VpcId) != str(subnet.Data.VpcId) || str(endpoint.Data.State) != "available" {
			continue
		}
		service := str(endpoint.Data.ServiceName)
		service = service[strings.LastIndexByte(service, '.')+1:]
		if service != "s3" && service != "dynamodb" && service != "kinesis" && service != "sqs" && service != "logs" && service != "lambda" && service != "bedrock-runtime" {
			continue
		}
		kind := str(endpoint.Data.VpcEndpointType)
		if kind == "Gateway" {
			if table == nil {
				continue
			}
			active := false
			for _, route := range table.Data.Routes {
				if str(route.State) == "active" && str(route.GatewayId) == endpoint.Key.ID && str(route.DestinationPrefixListId) == endpointPrefixList(subnet.Key.Scope, str(endpoint.Data.ServiceName)) {
					active = true
					break
				}
			}
			if active {
				gateway := out
				gateway.ServiceEndpoints = nil
				out.ServiceEndpoints = append(out.ServiceEndpoints, network.ServiceEndpoint{ID: endpoint.Key.ID, Service: service, Kind: kind, Network: gateway})
			}
			continue
		}
		if kind != "Interface" {
			continue
		}
		for _, id := range endpoint.Data.NetworkInterfaceIds {
			reservation, err := tx.NetworkInterface(ResourceKey{Scope: subnet.Key.Scope, ID: string(id)})
			if err != nil {
				return out, err
			}
			if reservation.NetworkControlOwnerID != endpoint.Key.ID || !boolValue(reservation.Data.RequesterManaged) {
				return out, failure("AuthFailure", "The endpoint interface has no immutable EC2 network control owner.")
			}
			spec, err := networkSpecification(ctx, tx, reservation)
			if err != nil {
				return out, err
			}
			out.ServiceEndpoints = append(out.ServiceEndpoints, network.ServiceEndpoint{ID: endpoint.Key.ID, Service: service, Kind: kind, PrivateDNS: boolValue(endpoint.Data.PrivateDnsEnabled), Network: spec})
			break // One available endpoint address; every selected ENI is authoritative.
		}
	}
	return out, nil
}

func lambdaFunctionNetwork(ctx context.Context, tx Reader, record NetworkInterfaceRecord) (TaskNetwork, error) {
	var out TaskNetwork
	var err error
	out.Interface, err = networkInterfaceProjection(ctx, tx, record)
	if err != nil {
		return out, err
	}
	out.Network, err = lambdaFunctionNetworkSpecification(ctx, tx, record)
	return out, err
}

type LambdaFunctionEndpointAccess struct {
	ID, VPCID, SourceIP, PolicyDocument string
}

// ResolveLambdaFunctionEndpoint derives endpoint admission from the exact ENI
// incarnation and its effective route table. No request header selects authority.
func (s *Service) ResolveLambdaFunctionEndpoint(ctx context.Context, function, incarnation, interfaceID, endpointID, kind, service string) (LambdaFunctionEndpointAccess, error) {
	var out LambdaFunctionEndpointAccess
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedLambdaFunctionInterface(ctx, tx, function, incarnation, interfaceID)
		if err != nil {
			return err
		}
		spec, err := lambdaFunctionNetworkSpecification(ctx, tx, record)
		if err != nil {
			return err
		}
		for _, candidate := range spec.ServiceEndpoints {
			if candidate.Kind != kind || candidate.Service != service || endpointID != "" && candidate.ID != endpointID {
				continue
			}
			endpoint, err := tx.VPCEndpoint(ResourceKey{Scope: record.Key.Scope, ID: candidate.ID})
			if err != nil {
				return err
			}
			out = LambdaFunctionEndpointAccess{ID: candidate.ID, VPCID: str(record.Data.VpcId), SourceIP: spec.Address.String(), PolicyDocument: str(endpoint.Data.PolicyDocument)}
			return nil
		}
		return failure("AuthFailure", "The service endpoint is not available to this Lambda function network incarnation.")
	})
	return out, err
}

// ObserveLambdaFunctionServiceEndpoint refreshes an exact native endpoint ENI,
// independently of this function's route selection. That distinction prevents a
// route withdrawal from deleting an endpoint still used by another function.
func (s *Service) ObserveLambdaFunctionServiceEndpoint(ctx context.Context, function, incarnation, interfaceID, endpointID, address string) (network.Specification, error) {
	var out network.Specification
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		source, err := ownedLambdaFunctionInterface(ctx, tx, function, incarnation, interfaceID)
		if err != nil {
			return err
		}
		if endpointID == "" {
			endpoints, err := tx.VPCEndpoints(source.Key.Scope)
			if err != nil {
				return err
			}
			for _, candidate := range endpoints {
				if str(candidate.Data.VpcId) == str(source.Data.VpcId) && str(candidate.Data.State) == "available" && str(candidate.Data.VpcEndpointType) == "Gateway" {
					out, err = networkSpecification(ctx, tx, source)
					return err
				}
			}
			return ErrNotFound
		}
		endpoint, err := tx.VPCEndpoint(ResourceKey{Scope: source.Key.Scope, ID: endpointID})
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if str(endpoint.Data.State) != "available" || str(endpoint.Data.VpcId) != str(source.Data.VpcId) {
			return ErrNotFound
		}
		for _, id := range endpoint.Data.NetworkInterfaceIds {
			record, err := tx.NetworkInterface(ResourceKey{Scope: source.Key.Scope, ID: string(id)})
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if record.NetworkControlOwnerID != endpointID || str(record.Data.PrivateIpAddress) != address {
				continue
			}
			out, err = networkSpecification(ctx, tx, record)
			return err
		}
		return ErrNotFound
	})
	return out, err
}
