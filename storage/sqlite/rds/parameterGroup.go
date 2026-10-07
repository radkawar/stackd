package rds

import (
	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func (r reader) ParameterGroup(k domain.Key) (domain.ParameterGroup, error) {
	row, e := r.q.GetParameterGroup(r.ctx, sqlcgen.GetParameterGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.ParameterGroup{}, missing(e)
	}
	return r.parameterGroup(row)
}

func (r reader) ParameterGroups(scope domain.Scope) ([]domain.ParameterGroup, error) {
	rows, e := r.q.ListParameterGroups(r.ctx, sqlcgen.ListParameterGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ParameterGroup, 0, len(rows))
	for _, row := range rows {

		v, e := r.parameterGroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)

	}
	return out, nil
}

func (r reader) parameterGroup(row sqlcgen.RdsParameterGroup) (domain.ParameterGroup, error) {
	v := domain.ParameterGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, ResourceID: row.ResourceID, Owner: domain.CloudFormationOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, Family: row.Family, Description: row.Description}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, v.ApplyMethods, e = r.parameters(v.Key)
	return v, e
}

func (w writer) PutParameterGroup(v domain.ParameterGroup) error {
	k := v.Key
	if e := w.q.PutParameterGroup(w.ctx, sqlcgen.PutParameterGroupParams{Partition: k.Partition, ResourceID: v.ResourceID, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Family: v.Family, Description: v.Description}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	return w.putParameters(k, v.Parameters, v.ApplyMethods)
}

func (w writer) DeleteParameterGroup(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteParameterGroup(w.ctx, sqlcgen.DeleteParameterGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
