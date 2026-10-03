package ec2

import (
	"database/sql"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func instanceMapping(row sqlcgen.Ec2InstanceMapping) (api.InstanceBlockDeviceMapping, error) {
	out := api.InstanceBlockDeviceMapping{DeviceName: stringPointer[api.String](row.DeviceName)}
	if row.EbsPresent {
		out.Ebs = &api.EbsInstanceBlockDevice{
			AssociatedResource: stringPointer[api.String](row.AssociatedResource), AttachTime: instanceDateTimePointer(row.AttachTime), DeleteOnTermination: boolPointer[api.Boolean](row.DeleteOnTermination), EbsCardIndex: integerPointer[api.Integer](row.EbsCardIndex),
			Status: stringPointer[api.AttachmentStatus](row.Status), VolumeId: stringPointer[api.String](row.VolumeID), VolumeOwnerId: stringPointer[api.String](row.VolumeOwnerID),
		}
		if err := unmarshalFields(jsonReadField{row.Operator, &out.Ebs.Operator}); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (r reader) InstanceVolumeAttachments(k domain.ResourceKey) ([]domain.InstanceVolumeAttachmentRecord, error) {
	rows, err := r.q.InstanceVolumeAttachments(r.ctx, sqlcgen.InstanceVolumeAttachmentsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, VolumeID: sql.NullString{String: k.ID, Valid: true}})
	if err != nil {
		return nil, err
	}
	out := make([]domain.InstanceVolumeAttachmentRecord, 0, len(rows))
	for _, row := range rows {
		mapping, err := instanceMapping(row)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.InstanceVolumeAttachmentRecord{InstanceKey: domain.ResourceKey{Scope: k.Scope, ID: row.ResourceID}, Mapping: mapping})
	}
	return out, nil
}

func (r reader) instanceChildren(row sqlcgen.Ec2Instance, out *domain.InstanceRecord) error {
	k := out.Key
	devices, err := r.q.ListInstanceMetadataDevices(r.ctx, sqlcgen.ListInstanceMetadataDevicesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return err
	}
	out.MetadataBlockDevices = devices
	if row.MappingsPresent {
		rows, err := r.q.ListInstanceMappings(r.ctx, sqlcgen.ListInstanceMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.BlockDeviceMappings = make(api.InstanceBlockDeviceMappingList, len(rows))
		for i, mapping := range rows {
			out.Data.BlockDeviceMappings[i], err = instanceMapping(mapping)
			if err != nil {
				return err
			}
		}
	}
	if row.NetworksPresent {
		rows, err := r.q.ListInstanceNetworks(r.ctx, sqlcgen.ListInstanceNetworksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.NetworkInterfaces = make(api.InstanceNetworkInterfaceList, len(rows))
		for i, network := range rows {
			out.Data.NetworkInterfaces[i] = api.InstanceNetworkInterface{NetworkInterfaceId: stringPointer[api.String](network.NetworkInterfaceID)}
		}
	}
	if row.GroupsPresent {
		rows, err := r.q.ListInstanceGroups(r.ctx, sqlcgen.ListInstanceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.SecurityGroups = make(api.GroupIdentifierList, len(rows))
		for i, group := range rows {
			out.Data.SecurityGroups[i] = api.GroupIdentifier{GroupId: stringPointer[api.String](group.GroupID), GroupName: stringPointer[api.String](group.GroupName)}
		}
	}
	if row.TagsPresent {
		rows, err := r.q.ListInstanceTags(r.ctx, sqlcgen.ListInstanceTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.Tags = make(api.TagList, len(rows))
		for i, tag := range rows {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return nil
}

func (w writer) putInstanceChildren(v domain.InstanceRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.DeleteInstanceMetadataDevices(w.ctx, sqlcgen.DeleteInstanceMetadataDevicesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, device := range v.MetadataBlockDevices {
		if err := w.q.PutInstanceMetadataDevice(w.ctx, sqlcgen.PutInstanceMetadataDeviceParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), DeviceName: device}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceMappings(w.ctx, sqlcgen.DeleteInstanceMappingsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, mapping := range d.BlockDeviceMappings {
		p := sqlcgen.PutInstanceMappingParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), DeviceName: nullableString(mapping.DeviceName), EbsPresent: mapping.Ebs != nil, Operator: []byte("null")}
		if e := mapping.Ebs; e != nil {
			p.AssociatedResource, p.AttachTime, p.DeleteOnTermination, p.EbsCardIndex = nullableString(e.AssociatedResource), instanceDateTime(e.AttachTime), nullableBool(e.DeleteOnTermination), nullableInteger(e.EbsCardIndex)
			p.Status, p.VolumeID, p.VolumeOwnerID = nullableString(e.Status), nullableString(e.VolumeId), nullableString(e.VolumeOwnerId)
			if err := marshalFields(jsonWriteField{&p.Operator, e.Operator}); err != nil {
				return err
			}
		}
		if err := w.q.PutInstanceMapping(w.ctx, p); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceNetworks(w.ctx, sqlcgen.DeleteInstanceNetworksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, network := range d.NetworkInterfaces {
		if err := w.q.PutInstanceNetwork(w.ctx, sqlcgen.PutInstanceNetworkParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), NetworkInterfaceID: nullableString(network.NetworkInterfaceId)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceGroups(w.ctx, sqlcgen.DeleteInstanceGroupsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, group := range d.SecurityGroups {
		if err := w.q.PutInstanceGroup(w.ctx, sqlcgen.PutInstanceGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), GroupID: nullableString(group.GroupId), GroupName: nullableString(group.GroupName)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteInstanceTags(w.ctx, sqlcgen.DeleteInstanceTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutInstanceTag(w.ctx, sqlcgen.PutInstanceTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
