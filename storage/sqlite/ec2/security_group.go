package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) SecurityGroup(k domain.ResourceKey) (domain.SecurityGroupRecord, error) {
	row, err := r.q.GetSecurityGroup(r.ctx, sqlcgen.GetSecurityGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.SecurityGroupRecord{}, missing(err)
	}
	return r.securityGroup(row)
}
func (r reader) SecurityGroups(s domain.Scope) ([]domain.SecurityGroupRecord, error) {
	rows, err := r.q.ListSecurityGroups(r.ctx, sqlcgen.ListSecurityGroupsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SecurityGroupRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.securityGroup(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) RegionalSecurityGroups(s domain.Scope) ([]domain.SecurityGroupRecord, error) {
	rows, err := r.q.ListRegionalSecurityGroups(r.ctx, sqlcgen.ListRegionalSecurityGroupsParams{Partition: s.Partition, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SecurityGroupRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.securityGroup(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) securityGroup(row sqlcgen.Ec2SecurityGroup) (domain.SecurityGroupRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.SecurityGroupRecord{Key: k, VPCOwnerAccountID: row.VpcOwnerAccountID}
	d := &out.Data
	d.Description = stringPointer[api.String](row.Description)
	d.GroupId = stringPointer[api.String](row.GroupID)
	d.GroupName = stringPointer[api.String](row.GroupName)
	d.OwnerId = stringPointer[api.String](row.OwnerID)
	d.SecurityGroupArn = stringPointer[api.String](row.SecurityGroupArn)
	d.VpcId = stringPointer[api.String](row.VpcID)
	if row.TagsPresent {
		values, err := r.securityGroupTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	if row.IpPermissionsPresent {
		values, err := r.securityGroupPermissions(k, false)
		if err != nil {
			return out, err
		}
		d.IpPermissions = values
	}
	if row.IpPermissionsEgressPresent {
		values, err := r.securityGroupPermissions(k, true)
		if err != nil {
			return out, err
		}
		d.IpPermissionsEgress = values
	}
	return out, nil
}
func (w writer) PutSecurityGroup(v domain.SecurityGroupRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutSecurityGroupParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		VpcOwnerAccountID:          v.VPCOwnerAccountID,
		Description:                nullableString(d.Description),
		GroupID:                    nullableString(d.GroupId),
		GroupName:                  nullableString(d.GroupName),
		OwnerID:                    nullableString(d.OwnerId),
		SecurityGroupArn:           nullableString(d.SecurityGroupArn),
		VpcID:                      nullableString(d.VpcId),
		TagsPresent:                d.Tags != nil,
		IpPermissionsPresent:       d.IpPermissions != nil,
		IpPermissionsEgressPresent: d.IpPermissionsEgress != nil,
	}
	if err := w.q.PutSecurityGroup(w.ctx, params); err != nil {
		return err
	}
	if err := w.putSecurityGroupTags(k, d.Tags); err != nil {
		return err
	}
	if err := w.putSecurityGroupPermissions(k, false, d.IpPermissions); err != nil {
		return err
	}
	if err := w.putSecurityGroupPermissions(k, true, d.IpPermissionsEgress); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteSecurityGroup(k domain.ResourceKey) error {
	return deleted(w.q.DeleteSecurityGroup(w.ctx, sqlcgen.DeleteSecurityGroupParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) securityGroupTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListSecurityGroupTags(r.ctx, sqlcgen.ListSecurityGroupTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) putSecurityGroupTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteSecurityGroupTags(w.ctx, sqlcgen.DeleteSecurityGroupTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutSecurityGroupTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutSecurityGroupTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) securityGroupPermissions(k domain.ResourceKey, egress bool) (api.IpPermissionList, error) {
	rows, err := r.q.ListSecurityGroupPermissions(r.ctx, sqlcgen.ListSecurityGroupPermissionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Egress: egress})
	if err != nil {
		return nil, err
	}
	out := make(api.IpPermissionList, len(rows))
	for i, row := range rows {
		d := &out[i]
		d.FromPort = integerPointer[api.Integer](row.FromPort)
		d.IpProtocol = stringPointer[api.String](row.IpProtocol)
		d.ToPort = integerPointer[api.Integer](row.ToPort)
		if err := unmarshalFields(jsonReadField{row.IpRanges, &d.IpRanges}, jsonReadField{row.Ipv6Ranges, &d.Ipv6Ranges}, jsonReadField{row.PrefixListIds, &d.PrefixListIds}, jsonReadField{row.UserIDGroupPairs, &d.UserIdGroupPairs}); err != nil {
			return out, err
		}
	}
	return out, nil
}
func (w writer) putSecurityGroupPermissions(k domain.ResourceKey, egress bool, values api.IpPermissionList) error {
	if err := w.q.DeleteSecurityGroupPermissions(w.ctx, sqlcgen.DeleteSecurityGroupPermissionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Egress: egress}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutSecurityGroupPermissionParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Egress: egress, Position: int64(i),
			FromPort:   nullableInteger(d.FromPort),
			IpProtocol: nullableString(d.IpProtocol),
			ToPort:     nullableInteger(d.ToPort),
		}
		if err := marshalFields(jsonWriteField{&params.IpRanges, d.IpRanges}, jsonWriteField{&params.Ipv6Ranges, d.Ipv6Ranges}, jsonWriteField{&params.PrefixListIds, d.PrefixListIds}, jsonWriteField{&params.UserIDGroupPairs, d.UserIdGroupPairs}); err != nil {
			return err
		}
		if err := w.q.PutSecurityGroupPermission(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
