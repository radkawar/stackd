package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) NetworkACL(k domain.ResourceKey) (domain.NetworkACLRecord, error) {
	row, err := r.q.GetNetworkAcl(r.ctx, sqlcgen.GetNetworkAclParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.NetworkACLRecord{}, missing(err)
	}
	return r.networkAcl(row)
}
func (r reader) NetworkACLs(s domain.Scope) ([]domain.NetworkACLRecord, error) {
	rows, err := r.q.ListNetworkAcls(r.ctx, sqlcgen.ListNetworkAclsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.NetworkACLRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.networkAcl(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) networkAcl(row sqlcgen.Ec2NetworkAcl) (domain.NetworkACLRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.NetworkACLRecord{Key: k}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	d := &out.Data
	d.IsDefault = boolPointer[api.Boolean](row.IsDefault)
	d.NetworkAclId = stringPointer[api.String](row.NetworkAclID)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.VpcId = stringPointer[api.String](row.VpcID)
	if row.TagsPresent {
		values, err := r.networkAclTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	if row.AssociationsPresent {
		values, err := r.networkAclAssociations(k)
		if err != nil {
			return out, err
		}
		d.Associations = values
	}
	if row.EntriesPresent {
		values, err := r.networkAclEntrys(k)
		if err != nil {
			return out, err
		}
		d.Entries = values
	}
	return out, nil
}
func (w writer) PutNetworkACL(v domain.NetworkACLRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutNetworkAclParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		IsDefault:           nullableBool(d.IsDefault),
		NetworkAclID:        nullableString(d.NetworkAclId),
		OwnerID:             nullableString(d.OwnerId),
		VpcID:               nullableString(d.VpcId),
		TagsPresent:         d.Tags != nil,
		AssociationsPresent: d.Associations != nil,
		EntriesPresent:      d.Entries != nil,
	}
	if err := w.q.PutNetworkAcl(w.ctx, params); err != nil {
		return err
	}
	if err := w.putNetworkAclTags(k, d.Tags); err != nil {
		return err
	}
	if err := w.putNetworkAclAssociations(k, d.Associations); err != nil {
		return err
	}
	if err := w.putNetworkAclEntrys(k, d.Entries); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteNetworkACL(k domain.ResourceKey) error {
	return deleted(w.q.DeleteNetworkAcl(w.ctx, sqlcgen.DeleteNetworkAclParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) networkAclTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListNetworkAclTags(r.ctx, sqlcgen.ListNetworkAclTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) putNetworkAclTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteNetworkAclTags(w.ctx, sqlcgen.DeleteNetworkAclTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutNetworkAclTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutNetworkAclTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) networkAclAssociations(k domain.ResourceKey) (api.NetworkAclAssociationList, error) {
	rows, err := r.q.ListNetworkAclAssociations(r.ctx, sqlcgen.ListNetworkAclAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.NetworkAclAssociationList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.NetworkAclAssociationId = stringPointer[api.String](row.NetworkAclAssociationID)
		d.NetworkAclId = stringPointer[api.String](row.NetworkAclID)
		d.SubnetId = stringPointer[api.String](row.SubnetID)
	}
	return out, nil
}
func (w writer) putNetworkAclAssociations(k domain.ResourceKey, values api.NetworkAclAssociationList) error {
	if err := w.q.DeleteNetworkAclAssociations(w.ctx, sqlcgen.DeleteNetworkAclAssociationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutNetworkAclAssociationParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			NetworkAclAssociationID: nullableString(d.NetworkAclAssociationId),
			NetworkAclID:            nullableString(d.NetworkAclId),
			SubnetID:                nullableString(d.SubnetId),
		}
		if err := w.q.PutNetworkAclAssociation(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) networkAclEntrys(k domain.ResourceKey) (api.NetworkAclEntryList, error) {
	rows, err := r.q.ListNetworkAclEntrys(r.ctx, sqlcgen.ListNetworkAclEntrysParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make(api.NetworkAclEntryList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.CidrBlock = stringPointer[api.String](row.CidrBlock)
		d.Egress = boolPointer[api.Boolean](row.Egress)
		d.Ipv6CidrBlock = stringPointer[api.String](row.Ipv6CidrBlock)
		d.Protocol = stringPointer[api.String](row.Protocol)
		d.RuleAction = stringPointer[api.RuleAction](row.RuleAction)
		d.RuleNumber = integerPointer[api.Integer](row.RuleNumber)
		if err := unmarshalFields(jsonReadField{row.IcmpTypeCode, &d.IcmpTypeCode}, jsonReadField{row.PortRange, &d.PortRange}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putNetworkAclEntrys(k domain.ResourceKey, values api.NetworkAclEntryList) error {
	if err := w.q.DeleteNetworkAclEntrys(w.ctx, sqlcgen.DeleteNetworkAclEntrysParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutNetworkAclEntryParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			CidrBlock:     nullableString(d.CidrBlock),
			Egress:        nullableBool(d.Egress),
			Ipv6CidrBlock: nullableString(d.Ipv6CidrBlock),
			Protocol:      nullableString(d.Protocol),
			RuleAction:    nullableString(d.RuleAction),
			RuleNumber:    nullableInteger(d.RuleNumber),
		}
		if err := marshalFields(jsonWriteField{&params.IcmpTypeCode, d.IcmpTypeCode}, jsonWriteField{&params.PortRange, d.PortRange}); err != nil {
			return err
		}
		if err := w.q.PutNetworkAclEntry(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
