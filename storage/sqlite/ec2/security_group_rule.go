package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) SecurityGroupRule(k domain.ResourceKey) (domain.SecurityGroupRuleRecord, error) {
	row, err := r.q.GetSecurityGroupRule(r.ctx, sqlcgen.GetSecurityGroupRuleParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.SecurityGroupRuleRecord{}, missing(err)
	}
	return r.securityGroupRule(row)
}
func (r reader) SecurityGroupRules(s domain.Scope) ([]domain.SecurityGroupRuleRecord, error) {
	rows, err := r.q.ListSecurityGroupRules(r.ctx, sqlcgen.ListSecurityGroupRulesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SecurityGroupRuleRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.securityGroupRule(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) securityGroupRule(row sqlcgen.Ec2SecurityGroupRule) (domain.SecurityGroupRuleRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.SecurityGroupRuleRecord{Key: k}
	d := &out.Data
	d.CidrIpv4 = stringPointer[api.String](row.CidrIpv4)
	d.CidrIpv6 = stringPointer[api.String](row.CidrIpv6)
	d.Description = stringPointer[api.String](row.Description)
	d.FromPort = integerPointer[api.Integer](row.FromPort)
	d.GroupId = stringPointer[api.SecurityGroupId](row.GroupID)
	d.GroupOwnerId = stringPointer[api.String](row.GroupOwnerID)
	d.IpProtocol = stringPointer[api.String](row.IpProtocol)
	d.IsEgress = boolPointer[api.Boolean](row.IsEgress)
	d.PrefixListId = stringPointer[api.PrefixListResourceId](row.PrefixListID)
	d.SecurityGroupRuleArn = stringPointer[api.String](row.SecurityGroupRuleArn)
	d.SecurityGroupRuleId = stringPointer[api.SecurityGroupRuleId](row.SecurityGroupRuleID)
	d.ToPort = integerPointer[api.Integer](row.ToPort)
	if err := unmarshalFields(jsonReadField{row.ReferencedGroupInfo, &d.ReferencedGroupInfo}); err != nil {
		return out, err
	}
	if row.TagsPresent {
		values, err := r.securityGroupRuleTags(k)
		if err != nil {
			return out, err
		}
		d.Tags = values
	}
	return out, nil
}
func (w writer) PutSecurityGroupRule(v domain.SecurityGroupRuleRecord) error {
	k, d := v.Key, &v.Data
	params := sqlcgen.PutSecurityGroupRuleParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		CidrIpv4:             nullableString(d.CidrIpv4),
		CidrIpv6:             nullableString(d.CidrIpv6),
		Description:          nullableString(d.Description),
		FromPort:             nullableInteger(d.FromPort),
		GroupID:              nullableString(d.GroupId),
		GroupOwnerID:         nullableString(d.GroupOwnerId),
		IpProtocol:           nullableString(d.IpProtocol),
		IsEgress:             nullableBool(d.IsEgress),
		PrefixListID:         nullableString(d.PrefixListId),
		SecurityGroupRuleArn: nullableString(d.SecurityGroupRuleArn),
		SecurityGroupRuleID:  nullableString(d.SecurityGroupRuleId),
		ToPort:               nullableInteger(d.ToPort),
		TagsPresent:          d.Tags != nil,
	}
	if err := marshalFields(jsonWriteField{&params.ReferencedGroupInfo, d.ReferencedGroupInfo}); err != nil {
		return err
	}
	if err := w.q.PutSecurityGroupRule(w.ctx, params); err != nil {
		return err
	}
	if err := w.putSecurityGroupRuleTags(k, d.Tags); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteSecurityGroupRule(k domain.ResourceKey) error {
	return deleted(w.q.DeleteSecurityGroupRule(w.ctx, sqlcgen.DeleteSecurityGroupRuleParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}

func (r reader) securityGroupRuleTags(k domain.ResourceKey) (api.TagList, error) {
	rows, err := r.q.ListSecurityGroupRuleTags(r.ctx, sqlcgen.ListSecurityGroupRuleTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
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
func (w writer) putSecurityGroupRuleTags(k domain.ResourceKey, values api.TagList) error {
	if err := w.q.DeleteSecurityGroupRuleTags(w.ctx, sqlcgen.DeleteSecurityGroupRuleTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i := range values {
		d := &values[i]
		params := sqlcgen.PutSecurityGroupRuleTagParams{
			Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i),
			Key:   nullableString(d.Key),
			Value: nullableString(d.Value),
		}
		if err := w.q.PutSecurityGroupRuleTag(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
