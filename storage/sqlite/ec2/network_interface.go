package ec2

import (
	"database/sql"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) NetworkInterface(k domain.ResourceKey) (domain.NetworkInterfaceRecord, error) {
	row, err := r.q.GetNetworkInterface(r.ctx, sqlcgen.GetNetworkInterfaceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.NetworkInterfaceRecord{}, missing(err)
	}
	return r.networkInterface(row)
}

func (r reader) NetworkInterfaces(scope domain.Scope) ([]domain.NetworkInterfaceRecord, error) {
	rows, err := r.q.ListNetworkInterfaces(r.ctx, sqlcgen.ListNetworkInterfacesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NetworkInterfaceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.networkInterface(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) RegionalNetworkInterfaces(scope domain.Scope) ([]domain.NetworkInterfaceRecord, error) {
	rows, err := r.q.ListRegionalNetworkInterfaces(r.ctx, sqlcgen.ListRegionalNetworkInterfacesParams{Partition: scope.Partition, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NetworkInterfaceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.networkInterface(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) networkInterface(row sqlcgen.Ec2NetworkInterface) (domain.NetworkInterfaceRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.NetworkInterfaceRecord{Key: k, TaskOwnerARN: row.TaskOwnerArn, TaskPublicNetworking: row.TaskPublicNetworking, SubnetOwnerAccountID: row.SubnetOwnerAccountID}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	out.LambdaMappingOwnerARN = row.LambdaMappingOwnerArn
	out.LambdaFunctionOwnerARN = row.LambdaFunctionOwnerArn
	out.LambdaFunctionOwnerIncarnation = row.LambdaFunctionOwnerIncarnation
	out.NetworkControlOwnerID = row.NetworkControlOwnerID
	d := &out.Data
	d.NetworkInterfaceId = stringPointer[api.String](row.NetworkInterfaceID)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.RequesterId = stringPointer[api.String](row.RequesterID)
	d.RequesterManaged = boolPointer[api.Boolean](row.RequesterManaged)
	d.AvailabilityZone = stringPointer[api.String](row.AvailabilityZone)
	d.AvailabilityZoneId = stringPointer[api.String](row.AvailabilityZoneID)
	d.SubnetId = stringPointer[api.String](row.SubnetID)
	d.VpcId = stringPointer[api.String](row.VpcID)
	d.MacAddress = stringPointer[api.String](row.MacAddress)
	d.Description = stringPointer[api.String](row.Description)
	d.InterfaceType = stringPointer[api.NetworkInterfaceType](row.InterfaceType)
	d.SourceDestCheck = boolPointer[api.Boolean](row.SourceDestCheck)
	d.Status = stringPointer[api.NetworkInterfaceStatus](row.Status)
	d.PrivateIpAddress = stringPointer[api.String](row.PrivateIpAddress)
	d.PrivateDnsName = stringPointer[api.String](row.PrivateDnsName)
	if row.AttachmentPresent {
		d.Attachment = &api.NetworkInterfaceAttachment{
			AttachmentId:        stringPointer[api.String](row.AttachmentID),
			InstanceId:          stringPointer[api.String](row.AttachmentInstanceID),
			InstanceOwnerId:     stringPointer[api.String](row.AttachmentInstanceOwnerID),
			DeleteOnTermination: boolPointer[api.Boolean](row.AttachmentDeleteOnTermination),
			DeviceIndex:         integerPointer[api.Integer](row.AttachmentDeviceIndex),
			NetworkCardIndex:    integerPointer[api.Integer](row.AttachmentNetworkCardIndex),
			Status:              stringPointer[api.AttachmentStatus](row.AttachmentStatus),
		}
		if row.AttachmentTime.Valid {
			d.Attachment.AttachTime = new(api.DateTime(row.AttachmentTime.Time))
		}
	}
	if row.OperatorPresent {
		d.Operator = &api.OperatorResponse{
			Managed:         boolPointer[api.Boolean](row.OperatorManaged),
			HiddenByDefault: boolPointer[api.Boolean](row.OperatorHiddenByDefault),
			Principal:       stringPointer[api.String](row.OperatorPrincipal),
		}
	}
	if row.Ipv6AddressesPresent {
		d.Ipv6Addresses = make(api.NetworkInterfaceIpv6AddressesList, 0)
	}
	if row.GroupsPresent {
		groups, err := r.q.ListNetworkInterfaceGroups(r.ctx, sqlcgen.ListNetworkInterfaceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.Groups = make(api.GroupIdentifierList, len(groups))
		for i, group := range groups {
			d.Groups[i] = api.GroupIdentifier{GroupId: stringPointer[api.String](group.GroupID), GroupName: stringPointer[api.String](group.GroupName)}
		}
	}
	if row.PrivateIpAddressesPresent {
		addresses, err := r.q.ListNetworkInterfacePrivateIPs(r.ctx, sqlcgen.ListNetworkInterfacePrivateIPsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.PrivateIpAddresses = make(api.NetworkInterfacePrivateIpAddressList, len(addresses))
		for i, address := range addresses {
			d.PrivateIpAddresses[i] = api.NetworkInterfacePrivateIpAddress{
				PrivateIpAddress: stringPointer[api.String](address.PrivateIpAddress),
				Primary:          boolPointer[api.Boolean](address.IsPrimary),
				PrivateDnsName:   stringPointer[api.String](address.PrivateDnsName),
			}
		}
	}
	if row.TagsPresent {
		tags, err := r.q.ListNetworkInterfaceTags(r.ctx, sqlcgen.ListNetworkInterfaceTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		d.TagSet = make(api.TagList, len(tags))
		for i, tag := range tags {
			d.TagSet[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return out, nil
}

func (w writer) PutNetworkInterface(v domain.NetworkInterfaceRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutNetworkInterfaceParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		SubnetOwnerAccountID:           v.SubnetOwnerAccountID,
		TaskOwnerArn:                   v.TaskOwnerARN,
		TaskPublicNetworking:           v.TaskPublicNetworking,
		LambdaMappingOwnerArn:          v.LambdaMappingOwnerARN,
		LambdaFunctionOwnerArn:         v.LambdaFunctionOwnerARN,
		LambdaFunctionOwnerIncarnation: v.LambdaFunctionOwnerIncarnation,
		NetworkControlOwnerID:          v.NetworkControlOwnerID,
		AttachmentPresent:              d.Attachment != nil,
		NetworkInterfaceID:             nullableString(d.NetworkInterfaceId),
		OwnerID:                        nullableString(d.OwnerId),
		RequesterID:                    nullableString(d.RequesterId),
		RequesterManaged:               nullableBool(d.RequesterManaged),
		AvailabilityZone:               nullableString(d.AvailabilityZone),
		AvailabilityZoneID:             nullableString(d.AvailabilityZoneId),
		SubnetID:                       nullableString(d.SubnetId),
		VpcID:                          nullableString(d.VpcId),
		MacAddress:                     nullableString(d.MacAddress),
		Description:                    nullableString(d.Description),
		InterfaceType:                  nullableString(d.InterfaceType),
		SourceDestCheck:                nullableBool(d.SourceDestCheck),
		Status:                         nullableString(d.Status),
		PrivateIpAddress:               nullableString(d.PrivateIpAddress),
		PrivateDnsName:                 nullableString(d.PrivateDnsName),
		GroupsPresent:                  d.Groups != nil,
		PrivateIpAddressesPresent:      d.PrivateIpAddresses != nil,
		Ipv6AddressesPresent:           d.Ipv6Addresses != nil,
		TagsPresent:                    d.TagSet != nil,
		OperatorPresent:                d.Operator != nil,
	}
	if d.Attachment != nil {
		params.AttachmentID = nullableString(d.Attachment.AttachmentId)
		params.AttachmentInstanceID = nullableString(d.Attachment.InstanceId)
		params.AttachmentInstanceOwnerID = nullableString(d.Attachment.InstanceOwnerId)
		params.AttachmentDeleteOnTermination = nullableBool(d.Attachment.DeleteOnTermination)
		params.AttachmentDeviceIndex = nullableInteger(d.Attachment.DeviceIndex)
		params.AttachmentNetworkCardIndex = nullableInteger(d.Attachment.NetworkCardIndex)
		params.AttachmentStatus = nullableString(d.Attachment.Status)
		if d.Attachment.AttachTime != nil {
			params.AttachmentTime = sql.NullTime{Time: *d.Attachment.AttachTime, Valid: true}
		}
	}
	if d.Operator != nil {
		params.OperatorManaged = nullableBool(d.Operator.Managed)
		params.OperatorHiddenByDefault = nullableBool(d.Operator.HiddenByDefault)
		params.OperatorPrincipal = nullableString(d.Operator.Principal)
	}
	if err := w.q.PutNetworkInterface(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteNetworkInterfaceGroups(w.ctx, sqlcgen.DeleteNetworkInterfaceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, group := range d.Groups {
		if err := w.q.PutNetworkInterfaceGroup(w.ctx, sqlcgen.PutNetworkInterfaceGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), GroupID: nullableString(group.GroupId), GroupName: nullableString(group.GroupName)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteNetworkInterfacePrivateIPs(w.ctx, sqlcgen.DeleteNetworkInterfacePrivateIPsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, address := range d.PrivateIpAddresses {
		if err := w.q.PutNetworkInterfacePrivateIP(w.ctx, sqlcgen.PutNetworkInterfacePrivateIPParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			PrivateIpAddress: nullableString(address.PrivateIpAddress), IsPrimary: nullableBool(address.Primary), PrivateDnsName: nullableString(address.PrivateDnsName),
		}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteNetworkInterfaceTags(w.ctx, sqlcgen.DeleteNetworkInterfaceTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.TagSet {
		if err := w.q.PutNetworkInterfaceTag(w.ctx, sqlcgen.PutNetworkInterfaceTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteNetworkInterface(k domain.ResourceKey) error {
	return deleted(w.q.DeleteNetworkInterface(w.ctx, sqlcgen.DeleteNetworkInterfaceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
