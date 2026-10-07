package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) ParameterGroup(k domain.Key) (domain.ParameterGroup, error) {
	row, e := r.q.GetParameterGroup(r.ctx, sqlcgen.GetParameterGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.ParameterGroup{}, missing(e)
	}
	return r.parametergroup(row)
}
func (r reader) ParameterGroups(sc domain.Scope) ([]domain.ParameterGroup, error) {
	rows, e := r.q.ListParameterGroups(r.ctx, sqlcgen.ListParameterGroupsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ParameterGroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.parametergroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) parametergroup(row sqlcgen.ElasticacheParameterGroup) (domain.ParameterGroup, error) {
	v := domain.ParameterGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Family: row.Family, Description: row.Description, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, e = r.parameters(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutParameterGroup(v domain.ParameterGroup) error {
	k := v.Key
	if e := w.q.PutParameterGroup(w.ctx, sqlcgen.PutParameterGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Family: v.Family, Description: v.Description, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putParameters(k, v.Parameters); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteParameterGroup(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteParameterGroup(w.ctx, sqlcgen.DeleteParameterGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
