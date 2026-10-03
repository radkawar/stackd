package ec2

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

func registerRouting(s *Service) {
	register(s, "CreateRouteTable", s.createRouteTable)
	register(s, "DescribeRouteTables", s.describeRouteTables)
	register(s, "DeleteRouteTable", s.deleteRouteTable)
	register(s, "AssociateRouteTable", s.associateRouteTable)
	register(s, "DisassociateRouteTable", s.disassociateRouteTable)
	register(s, "ReplaceRouteTableAssociation", s.replaceRouteTableAssociation)
	register(s, "CreateNetworkAcl", s.createNetworkACL)
	register(s, "DescribeNetworkAcls", s.describeNetworkACLs)
	register(s, "DeleteNetworkAcl", s.deleteNetworkACL)
	register(s, "CreateNetworkAclEntry", s.createNetworkACLEntry)
	register(s, "ReplaceNetworkAclEntry", s.replaceNetworkACLEntry)
	register(s, "DeleteNetworkAclEntry", s.deleteNetworkACLEntry)
	register(s, "ReplaceNetworkAclAssociation", s.replaceNetworkACLAssociation)
}

func routingBool(v *api.Boolean) bool { return v != nil && bool(*v) }

func associatedRouteState() *api.RouteTableAssociationState {
	return &api.RouteTableAssociationState{State: new(api.RouteTableAssociationStateCodeAssociated)}
}

func newRouteTable(vpc VPCRecord, id string, tags api.TagList) RouteTableRecord {
	return RouteTableRecord{Key: ResourceKey{Scope: vpc.Key.Scope, ID: id}, Data: api.RouteTable{
		RouteTableId: new(api.String(id)), VpcId: new(api.String(vpc.Key.ID)), OwnerId: new(api.String(vpc.Key.Scope.AccountID)), Tags: tags,
		Routes:       api.RouteList{{DestinationCidrBlock: new(api.String(str(vpc.Data.CidrBlock))), GatewayId: new(api.String("local")), Origin: new(api.RouteOriginCreateRouteTable), State: new(api.RouteStateActive)}},
		Associations: api.RouteTableAssociationList{}, PropagatingVgws: api.PropagatingVgwList{},
	}}
}

func createDefaultRouting(tx Transaction, vpc VPCRecord) (string, string, error) {
	id, err := tx.NextID(vpc.Key.Scope, "rtb")
	if err != nil {
		return "", "", err
	}
	associationID, err := tx.NextID(vpc.Key.Scope, "rtbassoc")
	if err != nil {
		return "", "", err
	}
	table := newRouteTable(vpc, id, api.TagList{})
	table.Data.Associations = api.RouteTableAssociationList{{Main: new(api.Boolean(true)), RouteTableAssociationId: new(api.String(associationID)), RouteTableId: new(api.String(id)), AssociationState: associatedRouteState()}}
	if err := tx.PutRouteTable(table); err != nil {
		return "", "", err
	}
	aclID, err := tx.NextID(vpc.Key.Scope, "acl")
	if err != nil {
		return "", "", err
	}
	if err := tx.PutNetworkACL(newNetworkACL(vpc, aclID, true, api.TagList{})); err != nil {
		return "", "", err
	}
	return id, aclID, nil
}

func routeTableFor(ctx context.Context, tx Reader, id string) (RouteTableRecord, error) {
	record, err := tx.RouteTable(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, missing("route-table", id)
	}
	return record, err
}

func routingVPCFor(ctx context.Context, tx Reader, id string) (VPCRecord, error) {
	record, err := tx.VPC(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, missing("vpc", id)
	}
	return record, err
}

func (s *Service) createRouteTable(ctx context.Context, tx Transaction, req *api.CreateRouteTableRequest) (*api.CreateRouteTableResult, error) {
	tags, err := CreationTags(req.TagSpecifications, "route-table")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "CreateRouteTable", "route-table", "*", tags); err != nil {
		return nil, err
	}
	vpc, err := routingVPCFor(ctx, tx, str(req.VpcId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateRouteTable", "vpc", vpc.Key.ID, vpc.Data.Tags); err != nil {
		return nil, err
	}
	creation, err := networkCreation(tx, vpc.Key.Scope, "CreateRouteTable", req.ClientToken, vpc.Key.ID, tags)
	if err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if creation.ResourceID != "" {
		record, err := tx.RouteTable(ResourceKey{Scope: vpc.Key.Scope, ID: creation.ResourceID})
		if errors.Is(err, ErrNotFound) {
			return nil, creationMismatch()
		}
		if err != nil {
			return nil, err
		}
		record.Data.Tags = creation.Tags
		return &api.CreateRouteTableResult{RouteTable: &record.Data, ClientToken: creation.clientToken()}, nil
	}
	id, err := tx.NextID(scopeFor(ctx), "rtb")
	if err != nil {
		return nil, err
	}
	record := newRouteTable(vpc, id, tags)
	if err := tx.PutRouteTable(record); err != nil {
		return nil, err
	}
	if creation.Key.Token != "" {
		creation.ResourceID = id
		if err := tx.PutNetworkCreation(creation); err != nil {
			return nil, err
		}
	}
	return &api.CreateRouteTableResult{RouteTable: &record.Data, ClientToken: creation.clientToken()}, nil
}

func (s *Service) describeRouteTables(ctx context.Context, tx Transaction, req *api.DescribeRouteTablesRequest) (*api.DescribeRouteTablesResult, error) {
	if err := s.authorize(ctx, "DescribeRouteTables", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleRouteTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.RouteTable, len(records))
	for _, record := range records {
		data := record.Data
		fields := map[string][]string{"route-table-id": {record.Key.ID}, "vpc-id": {str(data.VpcId)}, "owner-id": {str(data.OwnerId)}, "association.route-table-association-id": {}, "association.route-table-id": {}, "association.subnet-id": {}, "association.main": {}, "association.gateway-id": {}, "route.destination-cidr-block": {}, "route.gateway-id": {}, "route.origin": {}, "route.state": {}}
		for _, association := range data.Associations {
			fields["association.route-table-association-id"] = append(fields["association.route-table-association-id"], str(association.RouteTableAssociationId))
			fields["association.route-table-id"] = append(fields["association.route-table-id"], str(association.RouteTableId))
			fields["association.main"] = append(fields["association.main"], strconv.FormatBool(routingBool(association.Main)))
			if association.SubnetId != nil {
				fields["association.subnet-id"] = append(fields["association.subnet-id"], str(association.SubnetId))
			}
			if association.GatewayId != nil {
				fields["association.gateway-id"] = append(fields["association.gateway-id"], str(association.GatewayId))
			}
		}
		for _, route := range data.Routes {
			fields["route.destination-cidr-block"] = append(fields["route.destination-cidr-block"], str(route.DestinationCidrBlock))
			fields["route.gateway-id"] = append(fields["route.gateway-id"], str(route.GatewayId))
			fields["route.origin"] = append(fields["route.origin"], str(route.Origin))
			fields["route.state"] = append(fields["route.state"], str(route.State))
		}
		items = append(items, pageItem{ID: record.Key.ID, Tags: data.Tags, Fields: fields})
		byID[record.Key.ID] = data
	}
	ids, token, err := selectPage(ctx, "DescribeRouteTables", stringsOf(req.RouteTableIds), req.Filters, maxResults(req.MaxResults), req.NextToken, items)
	if err != nil {
		return nil, err
	}
	result := &api.DescribeRouteTablesResult{RouteTables: api.RouteTableList{}, NextToken: token}
	for _, id := range ids {
		result.RouteTables = append(result.RouteTables, byID[id])
	}
	return result, nil
}

func (s *Service) deleteRouteTable(ctx context.Context, tx Transaction, req *api.DeleteRouteTableRequest) (*emptyResult, error) {
	record, err := routeTableFor(ctx, tx, str(req.RouteTableId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteRouteTable", "route-table", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if len(record.Data.Associations) != 0 {
		return nil, failure("DependencyViolation", fmt.Sprintf("The routeTable '%s' has dependencies and cannot be deleted.", record.Key.ID))
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if err := tx.DeleteRouteTable(record.Key); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) associateRouteTable(ctx context.Context, tx Transaction, req *api.AssociateRouteTableRequest) (*api.AssociateRouteTableResult, error) {
	record, err := routeTableFor(ctx, tx, str(req.RouteTableId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "AssociateRouteTable", "route-table", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if req.GatewayId != nil || req.PublicIpv4Pool != nil {
		return nil, unsupported("Gateway and public IPv4 pool route-table associations are not supported")
	}
	subnet, err := tx.Subnet(key(ctx, str(req.SubnetId)))
	if errors.Is(err, ErrNotFound) {
		return nil, missing("subnet", str(req.SubnetId))
	}
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "AssociateRouteTable", "subnet", subnet.Key.ID, subnet.Data.Tags); err != nil {
		return nil, err
	}
	if str(subnet.Data.VpcId) != str(record.Data.VpcId) {
		return nil, failure("InvalidParameterValue", "Route table and subnet belong to different networks")
	}
	tables, err := tx.RouteTables(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		for _, association := range table.Data.Associations {
			if str(association.SubnetId) == subnet.Key.ID {
				return nil, failure("Resource.AlreadyAssociated", "The subnet already has an explicit route-table association")
			}
		}
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	id, err := tx.NextID(scopeFor(ctx), "rtbassoc")
	if err != nil {
		return nil, err
	}
	record.Data.Associations = append(record.Data.Associations, api.RouteTableAssociation{Main: new(api.Boolean(false)), RouteTableAssociationId: new(api.String(id)), RouteTableId: new(api.String(record.Key.ID)), SubnetId: new(api.String(subnet.Key.ID)), AssociationState: associatedRouteState()})
	if err := tx.PutRouteTable(record); err != nil {
		return nil, err
	}
	return &api.AssociateRouteTableResult{AssociationId: new(api.String(id)), AssociationState: associatedRouteState()}, nil
}

func routeAssociationFor(ctx context.Context, tx Reader, id string) (RouteTableRecord, int, error) {
	records, err := tx.RouteTables(scopeFor(ctx))
	if err != nil {
		return RouteTableRecord{}, 0, err
	}
	for _, record := range records {
		for i, association := range record.Data.Associations {
			if str(association.RouteTableAssociationId) == id {
				return record, i, nil
			}
		}
	}
	return RouteTableRecord{}, 0, failure("InvalidAssociationID.NotFound", fmt.Sprintf("The association ID '%s' does not exist", id))
}

func (s *Service) disassociateRouteTable(ctx context.Context, tx Transaction, req *api.DisassociateRouteTableRequest) (*emptyResult, error) {
	record, index, err := routeAssociationFor(ctx, tx, str(req.AssociationId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DisassociateRouteTable", "route-table", record.Key.ID, record.Data.Tags); err != nil {
		return nil, err
	}
	if routingBool(record.Data.Associations[index].Main) {
		return nil, failure("InvalidParameterValue", "The main route-table association cannot be disassociated")
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	record.Data.Associations = append(record.Data.Associations[:index], record.Data.Associations[index+1:]...)
	if err := tx.PutRouteTable(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) replaceRouteTableAssociation(ctx context.Context, tx Transaction, req *api.ReplaceRouteTableAssociationRequest) (*api.ReplaceRouteTableAssociationResult, error) {
	source, index, err := routeAssociationFor(ctx, tx, str(req.AssociationId))
	if err != nil {
		return nil, err
	}
	target, err := routeTableFor(ctx, tx, str(req.RouteTableId))
	if err != nil {
		return nil, err
	}
	for _, record := range []RouteTableRecord{source, target} {
		if err := s.authorize(ctx, "ReplaceRouteTableAssociation", "route-table", record.Key.ID, record.Data.Tags); err != nil {
			return nil, err
		}
	}
	if str(source.Data.VpcId) != str(target.Data.VpcId) {
		return nil, failure("InvalidParameterValue", "Route tables belong to different networks")
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	id, err := tx.NextID(scopeFor(ctx), "rtbassoc")
	if err != nil {
		return nil, err
	}
	association := source.Data.Associations[index]
	association.RouteTableAssociationId = new(api.String(id))
	association.RouteTableId = new(api.String(target.Key.ID))
	association.AssociationState = associatedRouteState()
	if source.Key == target.Key {
		source.Data.Associations[index] = association
		if err := tx.PutRouteTable(source); err != nil {
			return nil, err
		}
	} else {
		source.Data.Associations = append(source.Data.Associations[:index], source.Data.Associations[index+1:]...)
		target.Data.Associations = append(target.Data.Associations, association)
		if err := tx.PutRouteTable(source); err != nil {
			return nil, err
		}
		if err := tx.PutRouteTable(target); err != nil {
			return nil, err
		}
	}
	return &api.ReplaceRouteTableAssociationResult{NewAssociationId: new(api.String(id)), AssociationState: associatedRouteState()}, nil
}
