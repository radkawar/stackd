package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) VPC(k domain.ResourceKey) (domain.VPCRecord, error) {
	row, err := r.q.GetVpc(r.ctx, sqlcgen.GetVpcParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.VPCRecord{}, missing(err)
	}
	return r.vpc(row)
}
func (r reader) VPCs(s domain.Scope) ([]domain.VPCRecord, error) {
	rows, err := r.q.ListVpcs(r.ctx, sqlcgen.ListVpcsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VPCRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.vpc(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) vpc(row sqlcgen.Ec2Vpc) (domain.VPCRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.VPCRecord{Key: k}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d := &out.Data
	d.CidrBlock = stringPointer[api.String](row.CidrBlock)
	d.DhcpOptionsId = stringPointer[api.String](row.DhcpOptionsID)
	d.InstanceTenancy = stringPointer[api.Tenancy](row.InstanceTenancy)
	d.IsDefault = boolPointer[api.Boolean](row.IsDefault)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.State = stringPointer[api.VpcState](row.State)
	d.VpcId = stringPointer[api.String](row.VpcID)
	if err := unmarshalFields(jsonReadField{row.BlockPublicAccessStates, &d.BlockPublicAccessStates}, jsonReadField{row.EncryptionControl, &d.EncryptionControl}); err != nil {
		return out, err
	}
	out.DNSHostnames = row.DnsHostnames
	out.DNSSupport = row.DnsSupport
	out.NetworkAddressUsageMetrics = row.NetworkAddressUsageMetrics
	if row.TagsPresent {
		values, err := r.vpcTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	if row.CidrBlockAssociationSetPresent {
		values, err := r.vpcCidrAssociations(k)
		if err != nil {
			return out, err
		}
		d.CidrBlockAssociationSet = values
	}
	if row.Ipv6CidrBlockAssociationSetPresent {
		values, err := r.vpcIpv6Associations(k)
		if err != nil {
			return out, err
		}
		d.Ipv6CidrBlockAssociationSet = values
	}
	return out, nil
}
func (w writer) PutVPC(v domain.VPCRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutVpcParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		CidrBlock:                          nullableString(d.CidrBlock),
		DhcpOptionsID:                      nullableString(d.DhcpOptionsId),
		InstanceTenancy:                    nullableString(d.InstanceTenancy),
		IsDefault:                          nullableBool(d.IsDefault),
		OwnerID:                            nullableString(d.OwnerId),
		State:                              nullableString(d.State),
		VpcID:                              nullableString(d.VpcId),
		DnsHostnames:                       v.DNSHostnames,
		DnsSupport:                         v.DNSSupport,
		NetworkAddressUsageMetrics:         v.NetworkAddressUsageMetrics,
		TagsPresent:                        d.Tags != nil,
		CidrBlockAssociationSetPresent:     d.CidrBlockAssociationSet != nil,
		Ipv6CidrBlockAssociationSetPresent: d.Ipv6CidrBlockAssociationSet != nil,
	}
	if err := marshalFields(jsonWriteField{&params.BlockPublicAccessStates, d.BlockPublicAccessStates}, jsonWriteField{&params.EncryptionControl, encryptionControlJSON(d.EncryptionControl)}); err != nil {
		return err
	}
	if err := w.q.PutVpc(w.ctx, params); err != nil {
		return err
	}
	if err := w.putVpcTags(k, d.Tags); err != nil {
		return err
	}
	if err := w.putVpcCidrAssociations(k, d.CidrBlockAssociationSet); err != nil {
		return err
	}
	if err := w.putVpcIpv6Associations(k, d.Ipv6CidrBlockAssociationSet); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteVPC(k domain.ResourceKey) error {
	return deleted(w.q.DeleteVpc(w.ctx, sqlcgen.DeleteVpcParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) vpcTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListVpcTags(r.ctx, sqlcgen.ListVpcTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) putVpcTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteVpcTags(w.ctx, sqlcgen.DeleteVpcTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutVpcTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutVpcTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) vpcCidrAssociations(k domain.ResourceKey) (api.VpcCidrBlockAssociationSet, error) {
	rows, err := r.q.ListVpcCidrAssociations(r.ctx, sqlcgen.ListVpcCidrAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.VpcCidrBlockAssociationSet, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.AssociationId = stringPointer[api.String](row.AssociationID)
		d.CidrBlock = stringPointer[api.String](row.CidrBlock)
		if err := unmarshalFields(jsonReadField{row.CidrBlockState, &d.CidrBlockState}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putVpcCidrAssociations(k domain.ResourceKey, values api.VpcCidrBlockAssociationSet) error {
	if err := w.q.DeleteVpcCidrAssociations(w.ctx, sqlcgen.DeleteVpcCidrAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutVpcCidrAssociationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			AssociationID: nullableString(d.AssociationId),
			CidrBlock:     nullableString(d.CidrBlock),
		}
		if err := marshalFields(jsonWriteField{&params.CidrBlockState, d.CidrBlockState}); err != nil {
			return err
		}
		if err := w.q.PutVpcCidrAssociation(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) vpcIpv6Associations(k domain.ResourceKey) (api.VpcIpv6CidrBlockAssociationSet, error) {
	rows, err := r.q.ListVpcIpv6Associations(r.ctx, sqlcgen.ListVpcIpv6AssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.VpcIpv6CidrBlockAssociationSet, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.AssociationId = stringPointer[api.String](row.AssociationID)
		d.IpSource = stringPointer[api.IpSource](row.IpSource)
		d.Ipv6AddressAttribute = stringPointer[api.Ipv6AddressAttribute](row.Ipv6AddressAttribute)
		d.Ipv6CidrBlock = stringPointer[api.String](row.Ipv6CidrBlock)
		d.Ipv6Pool = stringPointer[api.String](row.Ipv6Pool)
		d.NetworkBorderGroup = stringPointer[api.String](row.NetworkBorderGroup)
		if err := unmarshalFields(jsonReadField{row.Ipv6CidrBlockState, &d.Ipv6CidrBlockState}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putVpcIpv6Associations(k domain.ResourceKey, values api.VpcIpv6CidrBlockAssociationSet) error {
	if err := w.q.DeleteVpcIpv6Associations(w.ctx, sqlcgen.DeleteVpcIpv6AssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutVpcIpv6AssociationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			AssociationID:        nullableString(d.AssociationId),
			IpSource:             nullableString(d.IpSource),
			Ipv6AddressAttribute: nullableString(d.Ipv6AddressAttribute),
			Ipv6CidrBlock:        nullableString(d.Ipv6CidrBlock),
			Ipv6Pool:             nullableString(d.Ipv6Pool),
			NetworkBorderGroup:   nullableString(d.NetworkBorderGroup),
		}
		if err := marshalFields(jsonWriteField{&params.Ipv6CidrBlockState, d.Ipv6CidrBlockState}); err != nil {
			return err
		}
		if err := w.q.PutVpcIpv6Association(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
