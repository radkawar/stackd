package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) Subnet(k domain.ResourceKey) (domain.SubnetRecord, error) {
	row, err := r.q.GetSubnet(r.ctx, sqlcgen.GetSubnetParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.SubnetRecord{}, missing(err)
	}
	return r.subnet(row)
}
func (r reader) Subnets(s domain.Scope) ([]domain.SubnetRecord, error) {
	rows, err := r.q.ListSubnets(r.ctx, sqlcgen.ListSubnetsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SubnetRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.subnet(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) subnet(row sqlcgen.Ec2Subnet) (domain.SubnetRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.SubnetRecord{Key: k}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d := &out.Data
	d.AssignIpv6AddressOnCreation = boolPointer[api.Boolean](row.AssignIpv6AddressOnCreation)
	d.AvailabilityZone = stringPointer[api.String](row.AvailabilityZone)
	d.AvailabilityZoneId = stringPointer[api.String](row.AvailabilityZoneID)
	d.AvailableIpAddressCount = integerPointer[api.Integer](row.AvailableIpAddressCount)
	d.CidrBlock = stringPointer[api.String](row.CidrBlock)
	d.CustomerOwnedIpv4Pool = stringPointer[api.CoipPoolId](row.CustomerOwnedIpv4Pool)
	d.DefaultForAz = boolPointer[api.Boolean](row.DefaultForAz)
	d.EnableDns64 = boolPointer[api.Boolean](row.EnableDns64)
	d.EnableLniAtDeviceIndex = integerPointer[api.Integer](row.EnableLniAtDeviceIndex)
	d.Ipv6Native = boolPointer[api.Boolean](row.Ipv6Native)
	d.MapCustomerOwnedIpOnLaunch = boolPointer[api.Boolean](row.MapCustomerOwnedIpOnLaunch)
	d.MapPublicIpOnLaunch = boolPointer[api.Boolean](row.MapPublicIpOnLaunch)
	d.OutpostArn = stringPointer[api.String](row.OutpostArn)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.State = stringPointer[api.SubnetState](row.State)
	d.SubnetArn = stringPointer[api.String](row.SubnetArn)
	d.SubnetId = stringPointer[api.String](row.SubnetID)
	d.Type = stringPointer[api.String](row.Type)
	d.VpcId = stringPointer[api.String](row.VpcID)
	if err := unmarshalFields(jsonReadField{row.BlockPublicAccessStates, &d.BlockPublicAccessStates}, jsonReadField{row.PrivateDnsNameOptionsOnLaunch, &d.PrivateDnsNameOptionsOnLaunch}); err != nil {
		return out, err
	}
	if row.TagsPresent {
		values, err := r.subnetTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	if row.Ipv6CidrBlockAssociationSetPresent {
		values, err := r.subnetIpv6Associations(k)
		if err != nil {
			return out, err
		}
		d.Ipv6CidrBlockAssociationSet = values
	}
	return out, nil
}
func (w writer) PutSubnet(v domain.SubnetRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutSubnetParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		AssignIpv6AddressOnCreation:        nullableBool(d.AssignIpv6AddressOnCreation),
		AvailabilityZone:                   nullableString(d.AvailabilityZone),
		AvailabilityZoneID:                 nullableString(d.AvailabilityZoneId),
		AvailableIpAddressCount:            nullableInteger(d.AvailableIpAddressCount),
		CidrBlock:                          nullableString(d.CidrBlock),
		CustomerOwnedIpv4Pool:              nullableString(d.CustomerOwnedIpv4Pool),
		DefaultForAz:                       nullableBool(d.DefaultForAz),
		EnableDns64:                        nullableBool(d.EnableDns64),
		EnableLniAtDeviceIndex:             nullableInteger(d.EnableLniAtDeviceIndex),
		Ipv6Native:                         nullableBool(d.Ipv6Native),
		MapCustomerOwnedIpOnLaunch:         nullableBool(d.MapCustomerOwnedIpOnLaunch),
		MapPublicIpOnLaunch:                nullableBool(d.MapPublicIpOnLaunch),
		OutpostArn:                         nullableString(d.OutpostArn),
		OwnerID:                            nullableString(d.OwnerId),
		State:                              nullableString(d.State),
		SubnetArn:                          nullableString(d.SubnetArn),
		SubnetID:                           nullableString(d.SubnetId),
		Type:                               nullableString(d.Type),
		VpcID:                              nullableString(d.VpcId),
		TagsPresent:                        d.Tags != nil,
		Ipv6CidrBlockAssociationSetPresent: d.Ipv6CidrBlockAssociationSet != nil,
	}
	if err := marshalFields(jsonWriteField{&params.BlockPublicAccessStates, d.BlockPublicAccessStates}, jsonWriteField{&params.PrivateDnsNameOptionsOnLaunch, d.PrivateDnsNameOptionsOnLaunch}); err != nil {
		return err
	}
	if err := w.q.PutSubnet(w.ctx, params); err != nil {
		return err
	}
	if err := w.putSubnetTags(k, d.Tags); err != nil {
		return err
	}
	if err := w.putSubnetIpv6Associations(k, d.Ipv6CidrBlockAssociationSet); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteSubnet(k domain.ResourceKey) error {
	return deleted(w.q.DeleteSubnet(w.ctx, sqlcgen.DeleteSubnetParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) subnetTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListSubnetTags(r.ctx, sqlcgen.ListSubnetTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) putSubnetTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteSubnetTags(w.ctx, sqlcgen.DeleteSubnetTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutSubnetTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutSubnetTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) subnetIpv6Associations(k domain.ResourceKey) (api.SubnetIpv6CidrBlockAssociationSet, error) {
	rows, err := r.q.ListSubnetIpv6Associations(r.ctx, sqlcgen.ListSubnetIpv6AssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.SubnetIpv6CidrBlockAssociationSet, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.AssociationId = stringPointer[api.SubnetCidrAssociationId](row.AssociationID)
		d.IpSource = stringPointer[api.IpSource](row.IpSource)
		d.Ipv6AddressAttribute = stringPointer[api.Ipv6AddressAttribute](row.Ipv6AddressAttribute)
		d.Ipv6CidrBlock = stringPointer[api.String](row.Ipv6CidrBlock)
		if err := unmarshalFields(jsonReadField{row.Ipv6CidrBlockState, &d.Ipv6CidrBlockState}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putSubnetIpv6Associations(k domain.ResourceKey, values api.SubnetIpv6CidrBlockAssociationSet) error {
	if err := w.q.DeleteSubnetIpv6Associations(w.ctx, sqlcgen.DeleteSubnetIpv6AssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutSubnetIpv6AssociationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			AssociationID:        nullableString(d.AssociationId),
			IpSource:             nullableString(d.IpSource),
			Ipv6AddressAttribute: nullableString(d.Ipv6AddressAttribute),
			Ipv6CidrBlock:        nullableString(d.Ipv6CidrBlock),
		}
		if err := marshalFields(jsonWriteField{&params.Ipv6CidrBlockState, d.Ipv6CidrBlockState}); err != nil {
			return err
		}
		if err := w.q.PutSubnetIpv6Association(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
