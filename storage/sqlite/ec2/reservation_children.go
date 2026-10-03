package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) reservationChildren(row sqlcgen.Ec2Reservation, out *domain.ReservationRecord) error {
	k, d := out.Key, &out.Input
	if row.InstancesPresent {
		rows, err := r.q.ListReservationInstances(r.ctx, sqlcgen.ListReservationInstancesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.InstanceIDs = make([]string, len(rows))
		for i, v := range rows {
			out.InstanceIDs[i] = v.InstanceID
		}
	}
	if row.MappingsPresent {
		rows, err := r.q.ListReservationMappings(r.ctx, sqlcgen.ListReservationMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		d.BlockDeviceMappings = make(api.BlockDeviceMappingRequestList, len(rows))
		for i, v := range rows {
			d.BlockDeviceMappings[i] = api.BlockDeviceMapping{DeviceName: stringPointer[api.String](v.DeviceName), NoDevice: stringPointer[api.String](v.NoDevice), VirtualName: stringPointer[api.String](v.VirtualName)}
			if err := unmarshalFields(jsonReadField{v.Ebs, &d.BlockDeviceMappings[i].Ebs}); err != nil {
				return err
			}
		}
	}
	if row.NetworksPresent {
		if err := r.reservationNetworks(k, d); err != nil {
			return err
		}
	}
	if row.GroupsPresent {
		rows, err := r.q.ListReservationGroups(r.ctx, sqlcgen.ListReservationGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		d.SecurityGroupIds = make(api.SecurityGroupIdStringList, len(rows))
		for i, v := range rows {
			d.SecurityGroupIds[i] = api.SecurityGroupId(v.GroupID)
		}
	}
	if row.TagsPresent {
		rows, err := r.q.ListReservationTagSpecifications(r.ctx, sqlcgen.ListReservationTagSpecificationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		d.TagSpecifications = make(api.TagSpecificationList, len(rows))
		for i, v := range rows {
			spec := &d.TagSpecifications[i]
			spec.ResourceType = stringPointer[api.ResourceType](v.ResourceType)
			if v.TagsPresent {
				tags, err := r.q.ListReservationTags(r.ctx, sqlcgen.ListReservationTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, SpecificationPosition: v.Position})
				if err != nil {
					return err
				}
				spec.Tags = make(api.TagList, len(tags))
				for j, tag := range tags {
					spec.Tags[j] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
				}
			}
		}
	}
	return nil
}

func (r reader) reservationNetworks(k domain.ResourceKey, d *api.RunInstancesRequest) error {
	rows, err := r.q.ListReservationNetworks(r.ctx, sqlcgen.ListReservationNetworksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return err
	}
	d.NetworkInterfaces = make(api.InstanceNetworkInterfaceSpecificationList, len(rows))
	for i, v := range rows {
		spec := &d.NetworkInterfaces[i]
		*spec = api.InstanceNetworkInterfaceSpecification{
			AssociateCarrierIpAddress: boolPointer[api.Boolean](v.AssociateCarrierIpAddress), AssociatePublicIpAddress: boolPointer[api.Boolean](v.AssociatePublicIpAddress), DeleteOnTermination: boolPointer[api.Boolean](v.DeleteOnTermination), Description: stringPointer[api.String](v.Description), DeviceIndex: integerPointer[api.Integer](v.DeviceIndex),
			InterfaceType: stringPointer[api.String](v.InterfaceType), NetworkCardIndex: integerPointer[api.Integer](v.NetworkCardIndex), NetworkInterfaceId: stringPointer[api.NetworkInterfaceId](v.NetworkInterfaceID), PrivateIpAddress: stringPointer[api.String](v.PrivateIpAddress), SubnetId: stringPointer[api.String](v.SubnetID),
		}
		if v.GroupsPresent {
			groups, err := r.q.ListReservationNetworkGroups(r.ctx, sqlcgen.ListReservationNetworkGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, NetworkPosition: v.Position})
			if err != nil {
				return err
			}
			spec.Groups = make(api.SecurityGroupIdStringList, len(groups))
			for j, group := range groups {
				spec.Groups[j] = api.SecurityGroupId(group.GroupID)
			}
		}
		if v.Ipv4PrefixesPresent {
			spec.Ipv4Prefixes = api.Ipv4PrefixList{}
		}
		if v.Ipv6AddressesPresent {
			spec.Ipv6Addresses = api.InstanceIpv6AddressList{}
		}
		if v.Ipv6PrefixesPresent {
			spec.Ipv6Prefixes = api.Ipv6PrefixList{}
		}
		if v.PrivateIpAddressesPresent {
			spec.PrivateIpAddresses = api.PrivateIpAddressSpecificationList{}
		}
	}
	return nil
}

func (w writer) putReservationChildren(v domain.ReservationRecord) error {
	k, d := v.Key, &v.Input
	if err := w.q.DeleteReservationInstances(w.ctx, sqlcgen.DeleteReservationInstancesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, id := range v.InstanceIDs {
		if err := w.q.PutReservationInstance(w.ctx, sqlcgen.PutReservationInstanceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), InstanceID: id}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteReservationMappings(w.ctx, sqlcgen.DeleteReservationMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, mapping := range d.BlockDeviceMappings {
		p := sqlcgen.PutReservationMappingParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), DeviceName: nullableString(mapping.DeviceName), NoDevice: nullableString(mapping.NoDevice), VirtualName: nullableString(mapping.VirtualName)}
		if err := marshalFields(jsonWriteField{&p.Ebs, mapping.Ebs}); err != nil {
			return err
		}
		if err := w.q.PutReservationMapping(w.ctx, p); err != nil {
			return err
		}
	}
	if err := w.putReservationNetworks(k, d); err != nil {
		return err
	}
	if err := w.q.DeleteReservationGroups(w.ctx, sqlcgen.DeleteReservationGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, group := range d.SecurityGroupIds {
		if err := w.q.PutReservationGroup(w.ctx, sqlcgen.PutReservationGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), GroupID: string(group)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteReservationTagSpecifications(w.ctx, sqlcgen.DeleteReservationTagSpecificationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, spec := range d.TagSpecifications {
		if err := w.q.PutReservationTagSpecification(w.ctx, sqlcgen.PutReservationTagSpecificationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), ResourceType: nullableString(spec.ResourceType), TagsPresent: spec.Tags != nil}); err != nil {
			return err
		}
		for j, tag := range spec.Tags {
			if err := w.q.PutReservationTag(w.ctx, sqlcgen.PutReservationTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, SpecificationPosition: int64(i), Position: int64(j), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) putReservationNetworks(k domain.ResourceKey, d *api.RunInstancesRequest) error {
	if err := w.q.DeleteReservationNetworks(w.ctx, sqlcgen.DeleteReservationNetworksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, spec := range d.NetworkInterfaces {
		p := sqlcgen.PutReservationNetworkParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			AssociateCarrierIpAddress: nullableBool(spec.AssociateCarrierIpAddress), AssociatePublicIpAddress: nullableBool(spec.AssociatePublicIpAddress), DeleteOnTermination: nullableBool(spec.DeleteOnTermination), Description: nullableString(spec.Description), DeviceIndex: nullableInteger(spec.DeviceIndex),
			InterfaceType: nullableString(spec.InterfaceType), NetworkCardIndex: nullableInteger(spec.NetworkCardIndex), NetworkInterfaceID: nullableString(spec.NetworkInterfaceId), PrivateIpAddress: nullableString(spec.PrivateIpAddress), SubnetID: nullableString(spec.SubnetId),
			GroupsPresent: spec.Groups != nil, Ipv4PrefixesPresent: spec.Ipv4Prefixes != nil, Ipv6AddressesPresent: spec.Ipv6Addresses != nil, Ipv6PrefixesPresent: spec.Ipv6Prefixes != nil, PrivateIpAddressesPresent: spec.PrivateIpAddresses != nil,
		}
		if err := w.q.PutReservationNetwork(w.ctx, p); err != nil {
			return err
		}
		for j, group := range spec.Groups {
			if err := w.q.PutReservationNetworkGroup(w.ctx, sqlcgen.PutReservationNetworkGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, NetworkPosition: int64(i), Position: int64(j), GroupID: string(group)}); err != nil {
				return err
			}
		}
	}
	return nil
}
