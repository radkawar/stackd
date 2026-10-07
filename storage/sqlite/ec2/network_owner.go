package ec2

import (
	"database/sql"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
	"strings"
	"time"
)

func networkOwnerTimestamp(v *time.Time) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: v.UTC().Format(time.RFC3339Nano), Valid: true}
}
func networkOwnerTime(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil
	}
	return &t
}

func (r reader) NatGateway(k domain.ResourceKey) (domain.NatGatewayRecord, error) {
	row, err := r.q.GetNatGateway(r.ctx, sqlcgen.GetNatGatewayParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.NatGatewayRecord{}, missing(err)
	}
	return r.natGateway(row)
}
func (r reader) NatGateways(s domain.Scope) ([]domain.NatGatewayRecord, error) {
	rows, err := r.q.ListNatGateways(r.ctx, sqlcgen.ListNatGatewaysParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NatGatewayRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.natGateway(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) natGateway(row sqlcgen.Ec2NatGateway) (domain.NatGatewayRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.NatGatewayRecord{Key: k}
	d := &out.Data
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d.NatGatewayId = stringPointer[api.String](row.NatGatewayID)
	d.VpcId = stringPointer[api.String](row.VpcID)
	d.SubnetId = stringPointer[api.String](row.SubnetID)
	d.ConnectivityType = stringPointer[api.ConnectivityType](row.ConnectivityType)
	d.AvailabilityMode = stringPointer[api.AvailabilityMode](row.AvailabilityMode)
	d.State = stringPointer[api.NatGatewayState](row.State)
	d.CreateTime = networkOwnerTime(row.CreateTime)
	d.DeleteTime = networkOwnerTime(row.DeleteTime)
	d.FailureCode = stringPointer[api.String](row.FailureCode)
	d.FailureMessage = stringPointer[api.String](row.FailureMessage)
	if row.TagsPresent {
		rows, err := r.q.ListNatGatewayTags(r.ctx, sqlcgen.ListNatGatewayTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.Tags = make(api.TagList, len(rows))
		for i, row := range rows {
			d.Tags[i] = api.Tag{Key: stringPointer[api.String](row.Key), Value: stringPointer[api.String](row.Value)}
		}
	}
	if row.NatGatewayAddressesPresent {
		rows, err := r.q.ListNatGatewayAddresses(r.ctx, sqlcgen.ListNatGatewayAddressesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.NatGatewayAddresses = make(api.NatGatewayAddressList, len(rows))
		for i, row := range rows {
			d.NatGatewayAddresses[i] = api.NatGatewayAddress{AllocationId: stringPointer[api.String](row.AllocationID), AssociationId: stringPointer[api.String](row.AssociationID), NetworkInterfaceId: stringPointer[api.String](row.NetworkInterfaceID), PrivateIp: stringPointer[api.String](row.PrivateIp), PublicIp: stringPointer[api.String](row.PublicIp), IsPrimary: boolPointer[api.Boolean](row.IsPrimary), Status: stringPointer[api.NatGatewayAddressStatus](row.Status)}
		}
	}
	return out, nil
}
func (w writer) PutNatGateway(v domain.NatGatewayRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.PutNatGateway(w.ctx, sqlcgen.PutNatGatewayParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, NatGatewayID: nullableString(d.NatGatewayId), VpcID: nullableString(d.VpcId), SubnetID: nullableString(d.SubnetId), ConnectivityType: nullableString(d.ConnectivityType), AvailabilityMode: nullableString(d.AvailabilityMode), State: nullableString(d.State), CreateTime: networkOwnerTimestamp(d.CreateTime), DeleteTime: networkOwnerTimestamp(d.DeleteTime), FailureCode: nullableString(d.FailureCode), FailureMessage: nullableString(d.FailureMessage), TagsPresent: d.Tags != nil, NatGatewayAddressesPresent: d.NatGatewayAddresses != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteNatGatewayTags(w.ctx, sqlcgen.DeleteNatGatewayTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.Tags {
		if err := w.q.PutNatGatewayTag(w.ctx, sqlcgen.PutNatGatewayTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(value.Key), Value: nullableString(value.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteNatGatewayAddresses(w.ctx, sqlcgen.DeleteNatGatewayAddressesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.NatGatewayAddresses {
		if err := w.q.PutNatGatewayAddress(w.ctx, sqlcgen.PutNatGatewayAddressParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), AllocationID: nullableString(value.AllocationId), AssociationID: nullableString(value.AssociationId), NetworkInterfaceID: nullableString(value.NetworkInterfaceId), PrivateIp: nullableString(value.PrivateIp), PublicIp: nullableString(value.PublicIp), IsPrimary: nullableBool(value.IsPrimary), Status: nullableString(value.Status)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteNatGateway(k domain.ResourceKey) error {
	return deleted(w.q.DeleteNatGateway(w.ctx, sqlcgen.DeleteNatGatewayParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
func (r reader) VPCEndpoint(k domain.ResourceKey) (domain.VPCEndpointRecord, error) {
	row, err := r.q.GetVPCEndpoint(r.ctx, sqlcgen.GetVPCEndpointParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.VPCEndpointRecord{}, missing(err)
	}
	return r.vpcEndpoint(row)
}
func (r reader) VPCEndpoints(s domain.Scope) ([]domain.VPCEndpointRecord, error) {
	rows, err := r.q.ListVPCEndpoints(r.ctx, sqlcgen.ListVPCEndpointsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VPCEndpointRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.vpcEndpoint(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) vpcEndpoint(row sqlcgen.Ec2VpcEndpoint) (domain.VPCEndpointRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.VPCEndpointRecord{Key: k}
	d := &out.Data
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d.VpcEndpointId = stringPointer[api.String](row.VpcEndpointID)
	d.VpcId = stringPointer[api.String](row.VpcID)
	d.VpcEndpointType = stringPointer[api.VpcEndpointType](row.VpcEndpointType)
	d.ServiceName = stringPointer[api.String](row.ServiceName)
	d.ServiceRegion = stringPointer[api.String](row.ServiceRegion)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.RequesterManaged = boolPointer[api.Boolean](row.RequesterManaged)
	d.State = stringPointer[api.State](row.State)
	d.CreationTimestamp = networkOwnerTime(row.CreationTimestamp)
	d.PolicyDocument = stringPointer[api.String](row.PolicyDocument)
	d.PrivateDnsEnabled = boolPointer[api.Boolean](row.PrivateDnsEnabled)
	d.IpAddressType = stringPointer[api.IpAddressType](row.IpAddressType)
	if row.DnsOptionsPresent {
		d.DnsOptions = &api.DnsOptions{DnsRecordIpType: stringPointer[api.DnsRecordIpType](row.DnsRecordIpType), PrivateDnsOnlyForInboundResolverEndpoint: boolPointer[api.Boolean](row.PrivateDnsOnlyForInboundResolverEndpoint)}
	}
	if row.TagsPresent {
		rows, err := r.q.ListVPCEndpointTags(r.ctx, sqlcgen.ListVPCEndpointTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.Tags = make(api.TagList, len(rows))
		for i, row := range rows {
			d.Tags[i] = api.Tag{Key: stringPointer[api.String](row.Key), Value: stringPointer[api.String](row.Value)}
		}
	}
	if row.GroupsPresent {
		rows, err := r.q.ListVPCEndpointGroups(r.ctx, sqlcgen.ListVPCEndpointGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.Groups = make(api.GroupIdentifierSet, len(rows))
		for i, row := range rows {
			d.Groups[i] = api.SecurityGroupIdentifier{GroupId: stringPointer[api.String](row.GroupID), GroupName: stringPointer[api.String](row.GroupName)}
		}
	}
	if row.RouteTableIdsPresent {
		rows, err := r.q.ListVPCEndpointRouteTables(r.ctx, sqlcgen.ListVPCEndpointRouteTablesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.RouteTableIds = make(api.ValueStringList, len(rows))
		for i, row := range rows {
			d.RouteTableIds[i] = api.String(row.Value.String)
		}
	}
	if row.SubnetIdsPresent {
		rows, err := r.q.ListVPCEndpointSubnets(r.ctx, sqlcgen.ListVPCEndpointSubnetsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.SubnetIds = make(api.ValueStringList, len(rows))
		for i, row := range rows {
			d.SubnetIds[i] = api.String(row.Value.String)
		}
	}
	if row.NetworkInterfaceIdsPresent {
		rows, err := r.q.ListVPCEndpointInterfaces(r.ctx, sqlcgen.ListVPCEndpointInterfacesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.NetworkInterfaceIds = make(api.ValueStringList, len(rows))
		for i, row := range rows {
			d.NetworkInterfaceIds[i] = api.String(row.Value.String)
		}
	}
	if row.DnsEntriesPresent {
		rows, err := r.q.ListVPCEndpointDNSEntries(r.ctx, sqlcgen.ListVPCEndpointDNSEntriesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.DnsEntries = make(api.DnsEntrySet, len(rows))
		for i, row := range rows {
			d.DnsEntries[i] = api.DnsEntry{DnsName: stringPointer[api.String](row.DnsName), HostedZoneId: stringPointer[api.String](row.HostedZoneID)}
		}
	}
	return out, nil
}
func (w writer) PutVPCEndpoint(v domain.VPCEndpointRecord) error {
	k, d := v.Key, &v.Data
	var dnsType sql.NullString
	var dnsInbound sql.NullBool
	if d.DnsOptions != nil {
		dnsType = nullableString(d.DnsOptions.DnsRecordIpType)
		dnsInbound = nullableBool(d.DnsOptions.PrivateDnsOnlyForInboundResolverEndpoint)
	}
	if err := w.q.PutVPCEndpoint(w.ctx, sqlcgen.PutVPCEndpointParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, VpcEndpointID: nullableString(d.VpcEndpointId), VpcID: nullableString(d.VpcId), VpcEndpointType: nullableString(d.VpcEndpointType), ServiceName: nullableString(d.ServiceName), ServiceRegion: nullableString(d.ServiceRegion), OwnerID: nullableString(d.OwnerId), RequesterManaged: nullableBool(d.RequesterManaged), State: nullableString(d.State), CreationTimestamp: networkOwnerTimestamp(d.CreationTimestamp), PolicyDocument: nullableString(d.PolicyDocument), PrivateDnsEnabled: nullableBool(d.PrivateDnsEnabled), IpAddressType: nullableString(d.IpAddressType), TagsPresent: d.Tags != nil, GroupsPresent: d.Groups != nil, RouteTableIdsPresent: d.RouteTableIds != nil, SubnetIdsPresent: d.SubnetIds != nil, NetworkInterfaceIdsPresent: d.NetworkInterfaceIds != nil, DnsEntriesPresent: d.DnsEntries != nil, DnsOptionsPresent: d.DnsOptions != nil, DnsRecordIpType: dnsType, PrivateDnsOnlyForInboundResolverEndpoint: dnsInbound}); err != nil {
		return err
	}
	if err := w.q.DeleteVPCEndpointTags(w.ctx, sqlcgen.DeleteVPCEndpointTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.Tags {
		if err := w.q.PutVPCEndpointTag(w.ctx, sqlcgen.PutVPCEndpointTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(value.Key), Value: nullableString(value.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVPCEndpointGroups(w.ctx, sqlcgen.DeleteVPCEndpointGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.Groups {
		if err := w.q.PutVPCEndpointGroup(w.ctx, sqlcgen.PutVPCEndpointGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), GroupID: nullableString(value.GroupId), GroupName: nullableString(value.GroupName)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVPCEndpointRouteTables(w.ctx, sqlcgen.DeleteVPCEndpointRouteTablesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.RouteTableIds {
		if err := w.q.PutVPCEndpointRouteTable(w.ctx, sqlcgen.PutVPCEndpointRouteTableParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Value: nullableString(&value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVPCEndpointSubnets(w.ctx, sqlcgen.DeleteVPCEndpointSubnetsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.SubnetIds {
		if err := w.q.PutVPCEndpointSubnet(w.ctx, sqlcgen.PutVPCEndpointSubnetParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Value: nullableString(&value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVPCEndpointInterfaces(w.ctx, sqlcgen.DeleteVPCEndpointInterfacesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.NetworkInterfaceIds {
		if err := w.q.PutVPCEndpointInterface(w.ctx, sqlcgen.PutVPCEndpointInterfaceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Value: nullableString(&value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVPCEndpointDNSEntries(w.ctx, sqlcgen.DeleteVPCEndpointDNSEntriesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, value := range d.DnsEntries {
		if err := w.q.PutVPCEndpointDNSEntry(w.ctx, sqlcgen.PutVPCEndpointDNSEntryParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), DnsName: nullableString(value.DnsName), HostedZoneID: nullableString(value.HostedZoneId)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteVPCEndpoint(k domain.ResourceKey) error {
	return deleted(w.q.DeleteVPCEndpoint(w.ctx, sqlcgen.DeleteVPCEndpointParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
func (r reader) NetworkOwnerCreation(k domain.NetworkCreationKey) (domain.NetworkOwnerCreationRecord, error) {
	row, err := r.q.GetNetworkOwnerCreation(r.ctx, sqlcgen.GetNetworkOwnerCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Action: k.Action, Token: k.Token})
	if err != nil {
		return domain.NetworkOwnerCreationRecord{}, missing(err)
	}
	return domain.NetworkOwnerCreationRecord{Key: k, ResourceID: row.ResourceID, Fingerprint: row.Fingerprint}, nil
}
func (w writer) PutNetworkOwnerCreation(v domain.NetworkOwnerCreationRecord) error {
	k := v.Key
	if k.Token == "" && strings.HasPrefix(k.Action, "CloudFormationRelation/") {
		return w.q.PutNetworkRelationOwner(w.ctx, sqlcgen.PutNetworkRelationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Action: k.Action, ResourceID: v.ResourceID, Fingerprint: v.Fingerprint})
	}
	return w.q.PutNetworkOwnerCreation(w.ctx, sqlcgen.PutNetworkOwnerCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Action: k.Action, Token: k.Token, ResourceID: v.ResourceID, Fingerprint: v.Fingerprint})
}
