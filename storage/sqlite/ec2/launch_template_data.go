package ec2

import (
	api "stackd/internal/awsapi/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) readLTVersion(row sqlcgen.Ec2LtVersionRecord) (api.RequestLaunchTemplateData, error) {

	var out api.RequestLaunchTemplateData

	if row.BlockDeviceMappingsPresent {
		rows, err := r.q.ListLTVersionBlockDeviceMappings(r.ctx, sqlcgen.ListLTVersionBlockDeviceMappingsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.BlockDeviceMappings = make(api.LaunchTemplateBlockDeviceMappingRequestList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionBlockDeviceMappings(row)
			if err != nil {
				return out, err
			}
			out.BlockDeviceMappings[i] = v
		}
	}

	if err := unmarshalFields(jsonReadField{row.CapacityReservationSpecification, &out.CapacityReservationSpecification}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.CpuOptions, &out.CpuOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.CreditSpecification, &out.CreditSpecification}); err != nil {
		return out, err
	}

	out.DisableApiStop = boolPointer[api.Boolean](row.DisableApiStop)

	out.DisableApiTermination = boolPointer[api.Boolean](row.DisableApiTermination)

	out.EbsOptimized = boolPointer[api.Boolean](row.EbsOptimized)

	if row.ElasticGpuSpecificationsPresent {
		rows, err := r.q.ListLTVersionElasticGpuSpecifications(r.ctx, sqlcgen.ListLTVersionElasticGpuSpecificationsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.ElasticGpuSpecifications = make(api.ElasticGpuSpecificationList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionElasticGpuSpecifications(row)
			if err != nil {
				return out, err
			}
			out.ElasticGpuSpecifications[i] = v
		}
	}

	if row.ElasticInferenceAcceleratorsPresent {
		rows, err := r.q.ListLTVersionElasticInferenceAccelerators(r.ctx, sqlcgen.ListLTVersionElasticInferenceAcceleratorsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.ElasticInferenceAccelerators = make(api.LaunchTemplateElasticInferenceAcceleratorList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionElasticInferenceAccelerators(row)
			if err != nil {
				return out, err
			}
			out.ElasticInferenceAccelerators[i] = v
		}
	}

	if err := unmarshalFields(jsonReadField{row.EnclaveOptions, &out.EnclaveOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.HibernationOptions, &out.HibernationOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.IamInstanceProfile, &out.IamInstanceProfile}); err != nil {
		return out, err
	}

	out.ImageId = stringPointer[api.ImageId](row.ImageID)

	out.InstanceInitiatedShutdownBehavior = stringPointer[api.ShutdownBehavior](row.InstanceInitiatedShutdownBehavior)

	if err := unmarshalFields(jsonReadField{row.InstanceMarketOptions, &out.InstanceMarketOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.InstanceRequirements, &out.InstanceRequirements}); err != nil {
		return out, err
	}

	out.InstanceType = stringPointer[api.InstanceType](row.InstanceType)

	out.KernelId = stringPointer[api.KernelId](row.KernelID)

	out.KeyName = stringPointer[api.KeyPairName](row.KeyName)

	if row.LicenseSpecificationsPresent {
		rows, err := r.q.ListLTVersionLicenseSpecifications(r.ctx, sqlcgen.ListLTVersionLicenseSpecificationsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.LicenseSpecifications = make(api.LaunchTemplateLicenseSpecificationListRequest, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionLicenseSpecifications(row)
			if err != nil {
				return out, err
			}
			out.LicenseSpecifications[i] = v
		}
	}

	if err := unmarshalFields(jsonReadField{row.MaintenanceOptions, &out.MaintenanceOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.MetadataOptions, &out.MetadataOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.Monitoring, &out.Monitoring}); err != nil {
		return out, err
	}

	if row.NetworkInterfacesPresent {
		rows, err := r.q.ListLTVersionNetworkInterfaces(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.NetworkInterfaces = make(api.LaunchTemplateInstanceNetworkInterfaceSpecificationRequestList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfaces(row)
			if err != nil {
				return out, err
			}
			out.NetworkInterfaces[i] = v
		}
	}

	if err := unmarshalFields(jsonReadField{row.NetworkPerformanceOptions, &out.NetworkPerformanceOptions}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.Operator, &out.Operator}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.Placement, &out.Placement}); err != nil {
		return out, err
	}

	if err := unmarshalFields(jsonReadField{row.PrivateDnsNameOptions, &out.PrivateDnsNameOptions}); err != nil {
		return out, err
	}

	out.RamDiskId = stringPointer[api.RamdiskId](row.RamDiskID)

	if row.SecondaryInterfacesPresent {
		rows, err := r.q.ListLTVersionSecondaryInterfaces(r.ctx, sqlcgen.ListLTVersionSecondaryInterfacesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.SecondaryInterfaces = make(api.LaunchTemplateInstanceSecondaryInterfaceSpecificationRequestList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionSecondaryInterfaces(row)
			if err != nil {
				return out, err
			}
			out.SecondaryInterfaces[i] = v
		}
	}

	if row.SecurityGroupIdsPresent {
		rows, err := r.q.ListLTVersionSecurityGroupIds(r.ctx, sqlcgen.ListLTVersionSecurityGroupIdsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.SecurityGroupIds = make(api.SecurityGroupIdStringList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionSecurityGroupIds(row)
			if err != nil {
				return out, err
			}
			out.SecurityGroupIds[i] = v
		}
	}

	if row.SecurityGroupsPresent {
		rows, err := r.q.ListLTVersionSecurityGroups(r.ctx, sqlcgen.ListLTVersionSecurityGroupsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.SecurityGroups = make(api.SecurityGroupStringList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionSecurityGroups(row)
			if err != nil {
				return out, err
			}
			out.SecurityGroups[i] = v
		}
	}

	if row.TagSpecificationsPresent {
		rows, err := r.q.ListLTVersionTagSpecifications(r.ctx, sqlcgen.ListLTVersionTagSpecificationsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version})
		if err != nil {
			return out, err
		}
		out.TagSpecifications = make(api.LaunchTemplateTagSpecificationRequestList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionTagSpecifications(row)
			if err != nil {
				return out, err
			}
			out.TagSpecifications[i] = v
		}
	}

	out.UserData = stringPointer[api.SensitiveUserData](row.UserData)

	return out, nil
}

func (w writer) writeLTVersion(p sqlcgen.PutLTVersionParams, d api.RequestLaunchTemplateData) error {

	p.BlockDeviceMappingsPresent = d.BlockDeviceMappings != nil

	if err := marshalFields(jsonWriteField{&p.CapacityReservationSpecification, d.CapacityReservationSpecification}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.CpuOptions, d.CpuOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.CreditSpecification, d.CreditSpecification}); err != nil {
		return err
	}

	p.DisableApiStop = nullableBool(d.DisableApiStop)

	p.DisableApiTermination = nullableBool(d.DisableApiTermination)

	p.EbsOptimized = nullableBool(d.EbsOptimized)

	p.ElasticGpuSpecificationsPresent = d.ElasticGpuSpecifications != nil

	p.ElasticInferenceAcceleratorsPresent = d.ElasticInferenceAccelerators != nil

	if err := marshalFields(jsonWriteField{&p.EnclaveOptions, d.EnclaveOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.HibernationOptions, d.HibernationOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.IamInstanceProfile, d.IamInstanceProfile}); err != nil {
		return err
	}

	p.ImageID = nullableString(d.ImageId)

	p.InstanceInitiatedShutdownBehavior = nullableString(d.InstanceInitiatedShutdownBehavior)

	if err := marshalFields(jsonWriteField{&p.InstanceMarketOptions, d.InstanceMarketOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.InstanceRequirements, d.InstanceRequirements}); err != nil {
		return err
	}

	p.InstanceType = nullableString(d.InstanceType)

	p.KernelID = nullableString(d.KernelId)

	p.KeyName = nullableString(d.KeyName)

	p.LicenseSpecificationsPresent = d.LicenseSpecifications != nil

	if err := marshalFields(jsonWriteField{&p.MaintenanceOptions, d.MaintenanceOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.MetadataOptions, d.MetadataOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.Monitoring, d.Monitoring}); err != nil {
		return err
	}

	p.NetworkInterfacesPresent = d.NetworkInterfaces != nil

	if err := marshalFields(jsonWriteField{&p.NetworkPerformanceOptions, d.NetworkPerformanceOptions}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.Operator, d.Operator}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.Placement, d.Placement}); err != nil {
		return err
	}

	if err := marshalFields(jsonWriteField{&p.PrivateDnsNameOptions, d.PrivateDnsNameOptions}); err != nil {
		return err
	}

	p.RamDiskID = nullableString(d.RamDiskId)

	p.SecondaryInterfacesPresent = d.SecondaryInterfaces != nil

	p.SecurityGroupIdsPresent = d.SecurityGroupIds != nil

	p.SecurityGroupsPresent = d.SecurityGroups != nil

	p.TagSpecificationsPresent = d.TagSpecifications != nil

	p.UserData = nullableString(d.UserData)

	if err := w.q.PutLTVersion(w.ctx, p); err != nil {
		return err
	}

	if err := w.q.ClearLTVersionBlockDeviceMappings(w.ctx, sqlcgen.ClearLTVersionBlockDeviceMappingsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.BlockDeviceMappings {
		if err := w.writeLTVersionBlockDeviceMappings(sqlcgen.PutLTVersionBlockDeviceMappingsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionElasticGpuSpecifications(w.ctx, sqlcgen.ClearLTVersionElasticGpuSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.ElasticGpuSpecifications {
		if err := w.writeLTVersionElasticGpuSpecifications(sqlcgen.PutLTVersionElasticGpuSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionElasticInferenceAccelerators(w.ctx, sqlcgen.ClearLTVersionElasticInferenceAcceleratorsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.ElasticInferenceAccelerators {
		if err := w.writeLTVersionElasticInferenceAccelerators(sqlcgen.PutLTVersionElasticInferenceAcceleratorsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionLicenseSpecifications(w.ctx, sqlcgen.ClearLTVersionLicenseSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.LicenseSpecifications {
		if err := w.writeLTVersionLicenseSpecifications(sqlcgen.PutLTVersionLicenseSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionNetworkInterfaces(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.NetworkInterfaces {
		if err := w.writeLTVersionNetworkInterfaces(sqlcgen.PutLTVersionNetworkInterfacesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionSecondaryInterfaces(w.ctx, sqlcgen.ClearLTVersionSecondaryInterfacesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.SecondaryInterfaces {
		if err := w.writeLTVersionSecondaryInterfaces(sqlcgen.PutLTVersionSecondaryInterfacesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionSecurityGroupIds(w.ctx, sqlcgen.ClearLTVersionSecurityGroupIdsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.SecurityGroupIds {
		if err := w.writeLTVersionSecurityGroupIds(sqlcgen.PutLTVersionSecurityGroupIdsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionSecurityGroups(w.ctx, sqlcgen.ClearLTVersionSecurityGroupsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.SecurityGroups {
		if err := w.writeLTVersionSecurityGroups(sqlcgen.PutLTVersionSecurityGroupsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionTagSpecifications(w.ctx, sqlcgen.ClearLTVersionTagSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version}); err != nil {
		return err
	}

	for i, v := range d.TagSpecifications {
		if err := w.writeLTVersionTagSpecifications(sqlcgen.PutLTVersionTagSpecificationsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	return nil
}

func (r reader) readLTVersionBlockDeviceMappings(row sqlcgen.Ec2LtVersionBlockDeviceMappingsRecord) (api.LaunchTemplateBlockDeviceMappingRequest, error) {

	var out api.LaunchTemplateBlockDeviceMappingRequest

	out.DeviceName = stringPointer[api.String](row.DeviceName)

	if err := unmarshalFields(jsonReadField{row.Ebs, &out.Ebs}); err != nil {
		return out, err
	}

	out.NoDevice = stringPointer[api.String](row.NoDevice)

	out.VirtualName = stringPointer[api.String](row.VirtualName)

	return out, nil
}

func (w writer) writeLTVersionBlockDeviceMappings(p sqlcgen.PutLTVersionBlockDeviceMappingsParams, d api.LaunchTemplateBlockDeviceMappingRequest) error {

	p.DeviceName = nullableString(d.DeviceName)

	if err := marshalFields(jsonWriteField{&p.Ebs, d.Ebs}); err != nil {
		return err
	}

	p.NoDevice = nullableString(d.NoDevice)

	p.VirtualName = nullableString(d.VirtualName)

	if err := w.q.PutLTVersionBlockDeviceMappings(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionElasticGpuSpecifications(row sqlcgen.Ec2LtVersionElasticGpuSpecificationsRecord) (api.ElasticGpuSpecification, error) {

	var out api.ElasticGpuSpecification

	out.Type = stringPointer[api.String](row.Type)

	return out, nil
}

func (w writer) writeLTVersionElasticGpuSpecifications(p sqlcgen.PutLTVersionElasticGpuSpecificationsParams, d api.ElasticGpuSpecification) error {

	p.Type = nullableString(d.Type)

	if err := w.q.PutLTVersionElasticGpuSpecifications(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionElasticInferenceAccelerators(row sqlcgen.Ec2LtVersionElasticInferenceAcceleratorsRecord) (api.LaunchTemplateElasticInferenceAccelerator, error) {

	var out api.LaunchTemplateElasticInferenceAccelerator

	out.Count = integerPointer[api.LaunchTemplateElasticInferenceAcceleratorCount](row.Count)

	out.Type = stringPointer[api.String](row.Type)

	return out, nil
}

func (w writer) writeLTVersionElasticInferenceAccelerators(p sqlcgen.PutLTVersionElasticInferenceAcceleratorsParams, d api.LaunchTemplateElasticInferenceAccelerator) error {

	p.Count = nullableInteger(d.Count)

	p.Type = nullableString(d.Type)

	if err := w.q.PutLTVersionElasticInferenceAccelerators(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionLicenseSpecifications(row sqlcgen.Ec2LtVersionLicenseSpecificationsRecord) (api.LaunchTemplateLicenseConfigurationRequest, error) {

	var out api.LaunchTemplateLicenseConfigurationRequest

	out.LicenseConfigurationArn = stringPointer[api.String](row.LicenseConfigurationArn)

	return out, nil
}

func (w writer) writeLTVersionLicenseSpecifications(p sqlcgen.PutLTVersionLicenseSpecificationsParams, d api.LaunchTemplateLicenseConfigurationRequest) error {

	p.LicenseConfigurationArn = nullableString(d.LicenseConfigurationArn)

	if err := w.q.PutLTVersionLicenseSpecifications(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfaces(row sqlcgen.Ec2LtVersionNetworkInterfacesRecord) (api.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest, error) {

	var out api.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest

	out.AssociateCarrierIpAddress = boolPointer[api.Boolean](row.AssociateCarrierIpAddress)

	out.AssociatePublicIpAddress = boolPointer[api.Boolean](row.AssociatePublicIpAddress)

	if err := unmarshalFields(jsonReadField{row.ConnectionTrackingSpecification, &out.ConnectionTrackingSpecification}); err != nil {
		return out, err
	}

	out.DeleteOnTermination = boolPointer[api.Boolean](row.DeleteOnTermination)

	out.Description = stringPointer[api.String](row.Description)

	out.DeviceIndex = integerPointer[api.Integer](row.DeviceIndex)

	out.EnaQueueCount = integerPointer[api.Integer](row.EnaQueueCount)

	if err := unmarshalFields(jsonReadField{row.EnaSrdSpecification, &out.EnaSrdSpecification}); err != nil {
		return out, err
	}

	if row.GroupsPresent {
		rows, err := r.q.ListLTVersionNetworkInterfacesGroups(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesGroupsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.Groups = make(api.SecurityGroupIdStringList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfacesGroups(row)
			if err != nil {
				return out, err
			}
			out.Groups[i] = v
		}
	}

	out.InterfaceType = stringPointer[api.String](row.InterfaceType)

	out.Ipv4PrefixCount = integerPointer[api.Integer](row.Ipv4PrefixCount)

	if row.Ipv4PrefixesPresent {
		rows, err := r.q.ListLTVersionNetworkInterfacesIpv4Prefixes(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesIpv4PrefixesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.Ipv4Prefixes = make(api.Ipv4PrefixList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfacesIpv4Prefixes(row)
			if err != nil {
				return out, err
			}
			out.Ipv4Prefixes[i] = v
		}
	}

	out.Ipv6AddressCount = integerPointer[api.Integer](row.Ipv6AddressCount)

	if row.Ipv6AddressesPresent {
		rows, err := r.q.ListLTVersionNetworkInterfacesIpv6Addresses(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesIpv6AddressesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.Ipv6Addresses = make(api.InstanceIpv6AddressListRequest, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfacesIpv6Addresses(row)
			if err != nil {
				return out, err
			}
			out.Ipv6Addresses[i] = v
		}
	}

	out.Ipv6PrefixCount = integerPointer[api.Integer](row.Ipv6PrefixCount)

	if row.Ipv6PrefixesPresent {
		rows, err := r.q.ListLTVersionNetworkInterfacesIpv6Prefixes(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesIpv6PrefixesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.Ipv6Prefixes = make(api.Ipv6PrefixList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfacesIpv6Prefixes(row)
			if err != nil {
				return out, err
			}
			out.Ipv6Prefixes[i] = v
		}
	}

	out.NetworkCardIndex = integerPointer[api.Integer](row.NetworkCardIndex)

	out.NetworkInterfaceId = stringPointer[api.NetworkInterfaceId](row.NetworkInterfaceID)

	out.PrimaryIpv6 = boolPointer[api.Boolean](row.PrimaryIpv6)

	out.PrivateIpAddress = stringPointer[api.String](row.PrivateIpAddress)

	if row.PrivateIpAddressesPresent {
		rows, err := r.q.ListLTVersionNetworkInterfacesPrivateIpAddresses(r.ctx, sqlcgen.ListLTVersionNetworkInterfacesPrivateIpAddressesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.PrivateIpAddresses = make(api.PrivateIpAddressSpecificationList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionNetworkInterfacesPrivateIpAddresses(row)
			if err != nil {
				return out, err
			}
			out.PrivateIpAddresses[i] = v
		}
	}

	out.SecondaryPrivateIpAddressCount = integerPointer[api.Integer](row.SecondaryPrivateIpAddressCount)

	out.SubnetId = stringPointer[api.SubnetId](row.SubnetID)

	return out, nil
}

func (w writer) writeLTVersionNetworkInterfaces(p sqlcgen.PutLTVersionNetworkInterfacesParams, d api.LaunchTemplateInstanceNetworkInterfaceSpecificationRequest) error {

	p.AssociateCarrierIpAddress = nullableBool(d.AssociateCarrierIpAddress)

	p.AssociatePublicIpAddress = nullableBool(d.AssociatePublicIpAddress)

	if err := marshalFields(jsonWriteField{&p.ConnectionTrackingSpecification, d.ConnectionTrackingSpecification}); err != nil {
		return err
	}

	p.DeleteOnTermination = nullableBool(d.DeleteOnTermination)

	p.Description = nullableString(d.Description)

	p.DeviceIndex = nullableInteger(d.DeviceIndex)

	p.EnaQueueCount = nullableInteger(d.EnaQueueCount)

	if err := marshalFields(jsonWriteField{&p.EnaSrdSpecification, d.EnaSrdSpecification}); err != nil {
		return err
	}

	p.GroupsPresent = d.Groups != nil

	p.InterfaceType = nullableString(d.InterfaceType)

	p.Ipv4PrefixCount = nullableInteger(d.Ipv4PrefixCount)

	p.Ipv4PrefixesPresent = d.Ipv4Prefixes != nil

	p.Ipv6AddressCount = nullableInteger(d.Ipv6AddressCount)

	p.Ipv6AddressesPresent = d.Ipv6Addresses != nil

	p.Ipv6PrefixCount = nullableInteger(d.Ipv6PrefixCount)

	p.Ipv6PrefixesPresent = d.Ipv6Prefixes != nil

	p.NetworkCardIndex = nullableInteger(d.NetworkCardIndex)

	p.NetworkInterfaceID = nullableString(d.NetworkInterfaceId)

	p.PrimaryIpv6 = nullableBool(d.PrimaryIpv6)

	p.PrivateIpAddress = nullableString(d.PrivateIpAddress)

	p.PrivateIpAddressesPresent = d.PrivateIpAddresses != nil

	p.SecondaryPrivateIpAddressCount = nullableInteger(d.SecondaryPrivateIpAddressCount)

	p.SubnetID = nullableString(d.SubnetId)

	if err := w.q.PutLTVersionNetworkInterfaces(w.ctx, p); err != nil {
		return err
	}

	if err := w.q.ClearLTVersionNetworkInterfacesGroups(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesGroupsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.Groups {
		if err := w.writeLTVersionNetworkInterfacesGroups(sqlcgen.PutLTVersionNetworkInterfacesGroupsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionNetworkInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionNetworkInterfacesIpv4Prefixes(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesIpv4PrefixesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.Ipv4Prefixes {
		if err := w.writeLTVersionNetworkInterfacesIpv4Prefixes(sqlcgen.PutLTVersionNetworkInterfacesIpv4PrefixesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionNetworkInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionNetworkInterfacesIpv6Addresses(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesIpv6AddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.Ipv6Addresses {
		if err := w.writeLTVersionNetworkInterfacesIpv6Addresses(sqlcgen.PutLTVersionNetworkInterfacesIpv6AddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionNetworkInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionNetworkInterfacesIpv6Prefixes(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesIpv6PrefixesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.Ipv6Prefixes {
		if err := w.writeLTVersionNetworkInterfacesIpv6Prefixes(sqlcgen.PutLTVersionNetworkInterfacesIpv6PrefixesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionNetworkInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	if err := w.q.ClearLTVersionNetworkInterfacesPrivateIpAddresses(w.ctx, sqlcgen.ClearLTVersionNetworkInterfacesPrivateIpAddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.PrivateIpAddresses {
		if err := w.writeLTVersionNetworkInterfacesPrivateIpAddresses(sqlcgen.PutLTVersionNetworkInterfacesPrivateIpAddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionNetworkInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfacesGroups(row sqlcgen.Ec2LtVersionNetworkInterfacesGroupsRecord) (api.SecurityGroupId, error) {

	return api.SecurityGroupId(row.Value), nil
}

func (w writer) writeLTVersionNetworkInterfacesGroups(p sqlcgen.PutLTVersionNetworkInterfacesGroupsParams, d api.SecurityGroupId) error {

	p.Value = string(d)

	if err := w.q.PutLTVersionNetworkInterfacesGroups(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfacesIpv4Prefixes(row sqlcgen.Ec2LtVersionNetworkInterfacesIpv4PrefixesRecord) (api.Ipv4PrefixSpecificationRequest, error) {

	var out api.Ipv4PrefixSpecificationRequest

	out.Ipv4Prefix = stringPointer[api.String](row.Ipv4Prefix)

	return out, nil
}

func (w writer) writeLTVersionNetworkInterfacesIpv4Prefixes(p sqlcgen.PutLTVersionNetworkInterfacesIpv4PrefixesParams, d api.Ipv4PrefixSpecificationRequest) error {

	p.Ipv4Prefix = nullableString(d.Ipv4Prefix)

	if err := w.q.PutLTVersionNetworkInterfacesIpv4Prefixes(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfacesIpv6Addresses(row sqlcgen.Ec2LtVersionNetworkInterfacesIpv6AddressesRecord) (api.InstanceIpv6AddressRequest, error) {

	var out api.InstanceIpv6AddressRequest

	out.Ipv6Address = stringPointer[api.String](row.Ipv6Address)

	return out, nil
}

func (w writer) writeLTVersionNetworkInterfacesIpv6Addresses(p sqlcgen.PutLTVersionNetworkInterfacesIpv6AddressesParams, d api.InstanceIpv6AddressRequest) error {

	p.Ipv6Address = nullableString(d.Ipv6Address)

	if err := w.q.PutLTVersionNetworkInterfacesIpv6Addresses(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfacesIpv6Prefixes(row sqlcgen.Ec2LtVersionNetworkInterfacesIpv6PrefixesRecord) (api.Ipv6PrefixSpecificationRequest, error) {

	var out api.Ipv6PrefixSpecificationRequest

	out.Ipv6Prefix = stringPointer[api.String](row.Ipv6Prefix)

	return out, nil
}

func (w writer) writeLTVersionNetworkInterfacesIpv6Prefixes(p sqlcgen.PutLTVersionNetworkInterfacesIpv6PrefixesParams, d api.Ipv6PrefixSpecificationRequest) error {

	p.Ipv6Prefix = nullableString(d.Ipv6Prefix)

	if err := w.q.PutLTVersionNetworkInterfacesIpv6Prefixes(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionNetworkInterfacesPrivateIpAddresses(row sqlcgen.Ec2LtVersionNetworkInterfacesPrivateIpAddressesRecord) (api.PrivateIpAddressSpecification, error) {

	var out api.PrivateIpAddressSpecification

	out.Primary = boolPointer[api.Boolean](row.Primary)

	out.PrivateIpAddress = stringPointer[api.String](row.PrivateIpAddress)

	return out, nil
}

func (w writer) writeLTVersionNetworkInterfacesPrivateIpAddresses(p sqlcgen.PutLTVersionNetworkInterfacesPrivateIpAddressesParams, d api.PrivateIpAddressSpecification) error {

	p.Primary = nullableBool(d.Primary)

	p.PrivateIpAddress = nullableString(d.PrivateIpAddress)

	if err := w.q.PutLTVersionNetworkInterfacesPrivateIpAddresses(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionSecondaryInterfaces(row sqlcgen.Ec2LtVersionSecondaryInterfacesRecord) (api.LaunchTemplateInstanceSecondaryInterfaceSpecificationRequest, error) {

	var out api.LaunchTemplateInstanceSecondaryInterfaceSpecificationRequest

	out.DeleteOnTermination = boolPointer[api.Boolean](row.DeleteOnTermination)

	out.DeviceIndex = integerPointer[api.Integer](row.DeviceIndex)

	out.InterfaceType = stringPointer[api.SecondaryInterfaceType](row.InterfaceType)

	out.NetworkCardIndex = integerPointer[api.Integer](row.NetworkCardIndex)

	out.PrivateIpAddressCount = integerPointer[api.Integer](row.PrivateIpAddressCount)

	if row.PrivateIpAddressesPresent {
		rows, err := r.q.ListLTVersionSecondaryInterfacesPrivateIpAddresses(r.ctx, sqlcgen.ListLTVersionSecondaryInterfacesPrivateIpAddressesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.PrivateIpAddresses = make(api.SecondaryInterfacePrivateIpAddressSpecificationListRequest, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionSecondaryInterfacesPrivateIpAddresses(row)
			if err != nil {
				return out, err
			}
			out.PrivateIpAddresses[i] = v
		}
	}

	out.SecondarySubnetId = stringPointer[api.SecondarySubnetId](row.SecondarySubnetID)

	return out, nil
}

func (w writer) writeLTVersionSecondaryInterfaces(p sqlcgen.PutLTVersionSecondaryInterfacesParams, d api.LaunchTemplateInstanceSecondaryInterfaceSpecificationRequest) error {

	p.DeleteOnTermination = nullableBool(d.DeleteOnTermination)

	p.DeviceIndex = nullableInteger(d.DeviceIndex)

	p.InterfaceType = nullableString(d.InterfaceType)

	p.NetworkCardIndex = nullableInteger(d.NetworkCardIndex)

	p.PrivateIpAddressCount = nullableInteger(d.PrivateIpAddressCount)

	p.PrivateIpAddressesPresent = d.PrivateIpAddresses != nil

	p.SecondarySubnetID = nullableString(d.SecondarySubnetId)

	if err := w.q.PutLTVersionSecondaryInterfaces(w.ctx, p); err != nil {
		return err
	}

	if err := w.q.ClearLTVersionSecondaryInterfacesPrivateIpAddresses(w.ctx, sqlcgen.ClearLTVersionSecondaryInterfacesPrivateIpAddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.PrivateIpAddresses {
		if err := w.writeLTVersionSecondaryInterfacesPrivateIpAddresses(sqlcgen.PutLTVersionSecondaryInterfacesPrivateIpAddressesParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionSecondaryInterfacesPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	return nil
}

func (r reader) readLTVersionSecondaryInterfacesPrivateIpAddresses(row sqlcgen.Ec2LtVersionSecondaryInterfacesPrivateIpAddressesRecord) (api.SecondaryInterfacePrivateIpAddressSpecificationRequest, error) {

	var out api.SecondaryInterfacePrivateIpAddressSpecificationRequest

	out.PrivateIpAddress = stringPointer[api.String](row.PrivateIpAddress)

	return out, nil
}

func (w writer) writeLTVersionSecondaryInterfacesPrivateIpAddresses(p sqlcgen.PutLTVersionSecondaryInterfacesPrivateIpAddressesParams, d api.SecondaryInterfacePrivateIpAddressSpecificationRequest) error {

	p.PrivateIpAddress = nullableString(d.PrivateIpAddress)

	if err := w.q.PutLTVersionSecondaryInterfacesPrivateIpAddresses(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionSecurityGroupIds(row sqlcgen.Ec2LtVersionSecurityGroupIdsRecord) (api.SecurityGroupId, error) {

	return api.SecurityGroupId(row.Value), nil
}

func (w writer) writeLTVersionSecurityGroupIds(p sqlcgen.PutLTVersionSecurityGroupIdsParams, d api.SecurityGroupId) error {

	p.Value = string(d)

	if err := w.q.PutLTVersionSecurityGroupIds(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionSecurityGroups(row sqlcgen.Ec2LtVersionSecurityGroupsRecord) (api.SecurityGroupName, error) {

	return api.SecurityGroupName(row.Value), nil
}

func (w writer) writeLTVersionSecurityGroups(p sqlcgen.PutLTVersionSecurityGroupsParams, d api.SecurityGroupName) error {

	p.Value = string(d)

	if err := w.q.PutLTVersionSecurityGroups(w.ctx, p); err != nil {
		return err
	}

	return nil
}

func (r reader) readLTVersionTagSpecifications(row sqlcgen.Ec2LtVersionTagSpecificationsRecord) (api.LaunchTemplateTagSpecificationRequest, error) {

	var out api.LaunchTemplateTagSpecificationRequest

	out.ResourceType = stringPointer[api.ResourceType](row.ResourceType)

	if row.TagsPresent {
		rows, err := r.q.ListLTVersionTagSpecificationsTags(r.ctx, sqlcgen.ListLTVersionTagSpecificationsTagsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID, Version: row.Version, VersionPosition: row.VersionPosition})
		if err != nil {
			return out, err
		}
		out.Tags = make(api.TagList, len(rows))
		for i, row := range rows {
			v, err := r.readLTVersionTagSpecificationsTags(row)
			if err != nil {
				return out, err
			}
			out.Tags[i] = v
		}
	}

	return out, nil
}

func (w writer) writeLTVersionTagSpecifications(p sqlcgen.PutLTVersionTagSpecificationsParams, d api.LaunchTemplateTagSpecificationRequest) error {

	p.ResourceType = nullableString(d.ResourceType)

	p.TagsPresent = d.Tags != nil

	if err := w.q.PutLTVersionTagSpecifications(w.ctx, p); err != nil {
		return err
	}

	if err := w.q.ClearLTVersionTagSpecificationsTags(w.ctx, sqlcgen.ClearLTVersionTagSpecificationsTagsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition}); err != nil {
		return err
	}

	for i, v := range d.Tags {
		if err := w.writeLTVersionTagSpecificationsTags(sqlcgen.PutLTVersionTagSpecificationsTagsParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, ResourceID: p.ResourceID, Version: p.Version, VersionPosition: p.VersionPosition, VersionTagSpecificationsPosition: int64(i)}, v); err != nil {
			return err
		}
	}

	return nil
}

func (r reader) readLTVersionTagSpecificationsTags(row sqlcgen.Ec2LtVersionTagSpecificationsTagsRecord) (api.Tag, error) {

	var out api.Tag

	out.Key = stringPointer[api.String](row.Key)

	out.Value = stringPointer[api.String](row.Value)

	return out, nil
}

func (w writer) writeLTVersionTagSpecificationsTags(p sqlcgen.PutLTVersionTagSpecificationsTagsParams, d api.Tag) error {

	p.Key = nullableString(d.Key)

	p.Value = nullableString(d.Value)

	if err := w.q.PutLTVersionTagSpecificationsTags(w.ctx, p); err != nil {
		return err
	}

	return nil
}
