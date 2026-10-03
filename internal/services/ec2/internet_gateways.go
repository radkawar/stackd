package ec2

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/ec2"
)

func registerInternetGateways(s *Service) {
	register(s, "CreateInternetGateway", s.createInternetGateway)
	register(s, "DescribeInternetGateways", s.describeInternetGateways)
	register(s, "AttachInternetGateway", s.attachInternetGateway)
	register(s, "DetachInternetGateway", s.detachInternetGateway)
	register(s, "DeleteInternetGateway", s.deleteInternetGateway)
	register(s, "CreateRoute", s.createRoute)
	register(s, "ReplaceRoute", s.replaceRoute)
	register(s, "DeleteRoute", s.deleteRoute)
}

func (s *Service) createInternetGateway(ctx context.Context, tx Transaction, req *api.CreateInternetGatewayRequest) (*api.CreateInternetGatewayResult, error) {
	tags, err := CreationTags(req.TagSpecifications, "internet-gateway")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "CreateInternetGateway", "internet-gateway", "*", tags); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	id, err := tx.NextID(scopeFor(ctx), "igw")
	if err != nil {
		return nil, err
	}
	record := InternetGatewayRecord{Key: key(ctx, id), Data: api.InternetGateway{
		InternetGatewayId: new(api.String(id)), OwnerId: new(api.String(scopeFor(ctx).AccountID)),
		Attachments: api.InternetGatewayAttachmentList{}, Tags: tags,
	}}
	if err := tx.PutInternetGateway(record); err != nil {
		return nil, err
	}
	return &api.CreateInternetGatewayResult{InternetGateway: &record.Data}, nil
}

func (s *Service) describeInternetGateways(ctx context.Context, tx Transaction, req *api.DescribeInternetGatewaysRequest) (*api.DescribeInternetGatewaysResult, error) {
	if err := s.authorize(ctx, "DescribeInternetGateways", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleInternetGateways(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.InternetGateway, len(records))
	for _, record := range records {
		fields := map[string][]string{"internet-gateway-id": {record.Key.ID}, "owner-id": {str(record.Data.OwnerId)}}
		for _, attachment := range record.Data.Attachments {
			fields["attachment.vpc-id"] = append(fields["attachment.vpc-id"], str(attachment.VpcId))
			fields["attachment.state"] = append(fields["attachment.state"], str(attachment.State))
		}
		items = append(items, pageItem{ID: record.Key.ID, Tags: record.Data.Tags, Fields: fields})
		byID[record.Key.ID] = record.Data
	}
	ids, token, err := selectPage(ctx, "DescribeInternetGateways", stringsOf(req.InternetGatewayIds), req.Filters, maxResults(req.MaxResults), req.NextToken, items)
	if err != nil {
		return nil, err
	}
	result := &api.DescribeInternetGatewaysResult{InternetGateways: api.InternetGatewayList{}, NextToken: token}
	for _, id := range ids {
		result.InternetGateways = append(result.InternetGateways, byID[id])
	}
	return result, nil
}

// Read resource tags for IAM without letting missing resources preempt the native
// authorization-only dry run. Storage failures are never mistaken for absence.
func (s *Service) authorizeInternetGateway(ctx context.Context, tx Reader, action, id string) (InternetGatewayRecord, error) {
	record, err := tx.InternetGateway(key(ctx, id))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return record, err
	}
	if rejected := s.authorize(ctx, action, "internet-gateway", id, record.Data.Tags); rejected != nil {
		return record, rejected
	}
	return record, nil
}

func (s *Service) internetGatewayAttachment(ctx context.Context, tx Transaction, action, id, vpcID string, dry *api.Boolean) (InternetGatewayRecord, error) {
	gateway, err := s.authorizeInternetGateway(ctx, tx, action, id)
	if err != nil {
		return gateway, err
	}
	vpc, err := tx.VPC(key(ctx, vpcID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return gateway, err
	}
	if err := s.authorize(ctx, action, "vpc", vpcID, vpc.Data.Tags); err != nil {
		return gateway, err
	}
	if err := dryRun(dry); err != nil {
		return gateway, err
	}
	if gateway.Key.ID == "" {
		return gateway, missing("internet-gateway", id)
	}
	if vpc.Key.ID == "" {
		return gateway, missing("vpc", vpcID)
	}
	return gateway, nil
}

func (s *Service) attachInternetGateway(ctx context.Context, tx Transaction, req *api.AttachInternetGatewayRequest) (*emptyResult, error) {
	id, vpcID := str(req.InternetGatewayId), str(req.VpcId)
	gateway, err := s.internetGatewayAttachment(ctx, tx, "AttachInternetGateway", id, vpcID, req.DryRun)
	if err != nil {
		return nil, err
	}
	if len(gateway.Data.Attachments) > 0 {
		return nil, failure("Resource.AlreadyAssociated", fmt.Sprintf("resource %s is already attached to network %s", id, str(gateway.Data.Attachments[0].VpcId)))
	}
	gateways, err := tx.InternetGateways(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, other := range gateways {
		for _, attachment := range other.Data.Attachments {
			if str(attachment.VpcId) == vpcID {
				return nil, failure("InvalidParameterValue", "Network "+vpcID+" already has an internet gateway attached")
			}
		}
	}
	// EC2's native attachment state is "available", despite its Smithy enum.
	gateway.Data.Attachments = api.InternetGatewayAttachmentList{{VpcId: new(api.String(vpcID)), State: new(api.AttachmentStatus("available"))}}
	if err := tx.PutInternetGateway(gateway); err != nil {
		return nil, err
	}
	if err := updateInternetGatewayRoutes(tx, gateway); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) detachInternetGateway(ctx context.Context, tx Transaction, req *api.DetachInternetGatewayRequest) (*emptyResult, error) {
	id, vpcID := str(req.InternetGatewayId), str(req.VpcId)
	gateway, err := s.internetGatewayAttachment(ctx, tx, "DetachInternetGateway", id, vpcID, req.DryRun)
	if err != nil {
		return nil, err
	}
	if len(gateway.Data.Attachments) == 0 || str(gateway.Data.Attachments[0].VpcId) != vpcID {
		return nil, failure("Gateway.NotAttached", fmt.Sprintf("resource %s is not attached to network %s", id, vpcID))
	}
	addresses, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if str(address.Data.PublicIp) == "" || str(address.Data.NetworkInterfaceId) == "" {
			continue
		}
		eni, err := tx.NetworkInterface(key(ctx, str(address.Data.NetworkInterfaceId)))
		if err != nil {
			return nil, err
		}
		if str(eni.Data.VpcId) == vpcID {
			return nil, failure("DependencyViolation", "The VPC has mapped public addresses; unmap them before detaching the internet gateway.")
		}
	}
	gateway.Data.Attachments = api.InternetGatewayAttachmentList{}
	if err := tx.PutInternetGateway(gateway); err != nil {
		return nil, err
	}
	if err := updateInternetGatewayRoutes(tx, gateway); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) deleteInternetGateway(ctx context.Context, tx Transaction, req *api.DeleteInternetGatewayRequest) (*emptyResult, error) {
	id := str(req.InternetGatewayId)
	gateway, err := s.authorizeInternetGateway(ctx, tx, "DeleteInternetGateway", id)
	if err != nil {
		return nil, err
	}
	if err := dryRun(req.DryRun); err != nil {
		return nil, err
	}
	if gateway.Key.ID == "" {
		return nil, missing("internet-gateway", id)
	}
	if len(gateway.Data.Attachments) > 0 {
		return nil, failure("DependencyViolation", fmt.Sprintf("The internetGateway '%s' has dependencies and cannot be deleted.", id))
	}
	if err := updateInternetGatewayRoutes(tx, gateway); err != nil {
		return nil, err
	}
	if err := tx.DeleteInternetGateway(gateway.Key); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

// Gateway lifecycle and route state changes commit together. A dangling target
// remains visible after detach/delete and revives only in its original VPC.
func updateInternetGatewayRoutes(tx Transaction, gateway InternetGatewayRecord) error {
	tables, err := tx.RouteTables(gateway.Key.Scope)
	if err != nil {
		return err
	}
	for _, table := range tables {
		state := api.RouteStateBlackhole
		for _, attachment := range gateway.Data.Attachments {
			if str(attachment.VpcId) == str(table.Data.VpcId) {
				state = api.RouteStateActive
			}
		}
		changed := false
		for index := range table.Data.Routes {
			route := &table.Data.Routes[index]
			if str(route.GatewayId) == gateway.Key.ID && str(route.State) != string(state) {
				route.State = new(state)
				changed = true
			}
		}
		if changed {
			if err := tx.PutRouteTable(table); err != nil {
				return err
			}
		}
	}
	return nil
}
