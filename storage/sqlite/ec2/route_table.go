package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) RouteTable(k domain.ResourceKey) (domain.RouteTableRecord, error) {
	row, err := r.q.GetRouteTable(r.ctx, sqlcgen.GetRouteTableParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.RouteTableRecord{}, missing(err)
	}
	return r.routeTable(row)
}
func (r reader) RouteTables(s domain.Scope) ([]domain.RouteTableRecord, error) {
	rows, err := r.q.ListRouteTables(r.ctx, sqlcgen.ListRouteTablesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RouteTableRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.routeTable(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) routeTable(row sqlcgen.Ec2RouteTable) (domain.RouteTableRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.RouteTableRecord{Key: k}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d := &out.Data
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.RouteTableId = stringPointer[api.String](row.RouteTableID)
	d.VpcId = stringPointer[api.String](row.VpcID)
	if row.TagsPresent {
		values, err := r.routeTableTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	if row.AssociationsPresent {
		values, err := r.routeTableAssociations(k)
		if err != nil {
			return out, err
		}
		d.Associations = values
	}
	if row.PropagatingVgwsPresent {
		values, err := r.routeTablePropagations(k)
		if err != nil {
			return out, err
		}
		d.PropagatingVgws = values
	}
	if row.RoutesPresent {
		values, err := r.routeTableRoutes(k)
		if err != nil {
			return out, err
		}
		d.Routes = values
	}
	return out, nil
}
func (w writer) PutRouteTable(v domain.RouteTableRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutRouteTableParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		OwnerID:                nullableString(d.OwnerId),
		RouteTableID:           nullableString(d.RouteTableId),
		VpcID:                  nullableString(d.VpcId),
		TagsPresent:            d.Tags != nil,
		AssociationsPresent:    d.Associations != nil,
		PropagatingVgwsPresent: d.PropagatingVgws != nil,
		RoutesPresent:          d.Routes != nil,
	}
	if err := w.q.PutRouteTable(w.ctx, params); err != nil {
		return err
	}
	if err := w.putRouteTableTags(k, d.Tags); err != nil {
		return err
	}
	if err := w.putRouteTableAssociations(k, d.Associations); err != nil {
		return err
	}
	if err := w.putRouteTablePropagations(k, d.PropagatingVgws); err != nil {
		return err
	}
	if err := w.putRouteTableRoutes(k, d.Routes); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteRouteTable(k domain.ResourceKey) error {
	return deleted(w.q.DeleteRouteTable(w.ctx, sqlcgen.DeleteRouteTableParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) routeTableTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListRouteTableTags(r.ctx, sqlcgen.ListRouteTableTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.TagList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.Key = stringPointer[api.String](row.Key)
		d.Value = stringPointer[api.String](row.Value)
	}
	return out, nil
}
func (w writer) putRouteTableTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteRouteTableTags(w.ctx, sqlcgen.DeleteRouteTableTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutRouteTableTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutRouteTableTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) routeTableAssociations(k domain.ResourceKey) (api.RouteTableAssociationList, error) {
	rows, err := r.q.ListRouteTableAssociations(r.ctx, sqlcgen.ListRouteTableAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.RouteTableAssociationList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.GatewayId = stringPointer[api.String](row.GatewayID)
		d.Main = boolPointer[api.Boolean](row.Main)
		d.PublicIpv4Pool = stringPointer[api.String](row.PublicIpv4Pool)
		d.RouteTableAssociationId = stringPointer[api.String](row.RouteTableAssociationID)
		d.RouteTableId = stringPointer[api.String](row.RouteTableID)
		d.SubnetId = stringPointer[api.String](row.SubnetID)
		if err := unmarshalFields(jsonReadField{row.AssociationState, &d.AssociationState}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putRouteTableAssociations(k domain.ResourceKey, values api.RouteTableAssociationList) error {
	if err := w.q.DeleteRouteTableAssociations(w.ctx, sqlcgen.DeleteRouteTableAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutRouteTableAssociationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			GatewayID:               nullableString(d.GatewayId),
			Main:                    nullableBool(d.Main),
			PublicIpv4Pool:          nullableString(d.PublicIpv4Pool),
			RouteTableAssociationID: nullableString(d.RouteTableAssociationId),
			RouteTableID:            nullableString(d.RouteTableId),
			SubnetID:                nullableString(d.SubnetId),
		}
		if err := marshalFields(jsonWriteField{&params.AssociationState, d.AssociationState}); err != nil {
			return err
		}
		if err := w.q.PutRouteTableAssociation(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) routeTablePropagations(k domain.ResourceKey) (api.PropagatingVgwList, error) {
	rows, err := r.q.ListRouteTablePropagations(r.ctx, sqlcgen.ListRouteTablePropagationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.PropagatingVgwList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.GatewayId = stringPointer[api.String](row.GatewayID)
	}
	return out, nil
}
func (w writer) putRouteTablePropagations(k domain.ResourceKey, values api.PropagatingVgwList) error {
	if err := w.q.DeleteRouteTablePropagations(w.ctx, sqlcgen.DeleteRouteTablePropagationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutRouteTablePropagationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			GatewayID: nullableString(d.GatewayId),
		}
		if err := w.q.PutRouteTablePropagation(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) routeTableRoutes(k domain.ResourceKey) (api.RouteList, error) {
	rows, err := r.q.ListRouteTableRoutes(r.ctx, sqlcgen.ListRouteTableRoutesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.RouteList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.CarrierGatewayId = stringPointer[api.CarrierGatewayId](row.CarrierGatewayID)
		d.CoreNetworkArn = stringPointer[api.CoreNetworkArn](row.CoreNetworkArn)
		d.DestinationCidrBlock = stringPointer[api.String](row.DestinationCidrBlock)
		d.DestinationIpv6CidrBlock = stringPointer[api.String](row.DestinationIpv6CidrBlock)
		d.DestinationPrefixListId = stringPointer[api.String](row.DestinationPrefixListID)
		d.EgressOnlyInternetGatewayId = stringPointer[api.String](row.EgressOnlyInternetGatewayID)
		d.GatewayId = stringPointer[api.String](row.GatewayID)
		d.InstanceId = stringPointer[api.String](row.InstanceID)
		d.InstanceOwnerId = stringPointer[api.String](row.InstanceOwnerID)
		d.IpAddress = stringPointer[api.String](row.IpAddress)
		d.LocalGatewayId = stringPointer[api.String](row.LocalGatewayID)
		d.NatGatewayId = stringPointer[api.String](row.NatGatewayID)
		d.NetworkInterfaceId = stringPointer[api.String](row.NetworkInterfaceID)
		d.OdbNetworkArn = stringPointer[api.OdbNetworkArn](row.OdbNetworkArn)
		d.Origin = stringPointer[api.RouteOrigin](row.Origin)
		d.State = stringPointer[api.RouteState](row.State)
		d.TransitGatewayId = stringPointer[api.String](row.TransitGatewayID)
		d.VpcPeeringConnectionId = stringPointer[api.String](row.VpcPeeringConnectionID)
	}
	return out, nil
}
func (w writer) putRouteTableRoutes(k domain.ResourceKey, values api.RouteList) error {
	if err := w.q.DeleteRouteTableRoutes(w.ctx, sqlcgen.DeleteRouteTableRoutesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutRouteTableRouteParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			CarrierGatewayID:            nullableString(d.CarrierGatewayId),
			CoreNetworkArn:              nullableString(d.CoreNetworkArn),
			DestinationCidrBlock:        nullableString(d.DestinationCidrBlock),
			DestinationIpv6CidrBlock:    nullableString(d.DestinationIpv6CidrBlock),
			DestinationPrefixListID:     nullableString(d.DestinationPrefixListId),
			EgressOnlyInternetGatewayID: nullableString(d.EgressOnlyInternetGatewayId),
			GatewayID:                   nullableString(d.GatewayId),
			InstanceID:                  nullableString(d.InstanceId),
			InstanceOwnerID:             nullableString(d.InstanceOwnerId),
			IpAddress:                   nullableString(d.IpAddress),
			LocalGatewayID:              nullableString(d.LocalGatewayId),
			NatGatewayID:                nullableString(d.NatGatewayId),
			NetworkInterfaceID:          nullableString(d.NetworkInterfaceId),
			OdbNetworkArn:               nullableString(d.OdbNetworkArn),
			Origin:                      nullableString(d.Origin),
			State:                       nullableString(d.State),
			TransitGatewayID:            nullableString(d.TransitGatewayId),
			VpcPeeringConnectionID:      nullableString(d.VpcPeeringConnectionId),
		}
		if err := w.q.PutRouteTableRoute(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
