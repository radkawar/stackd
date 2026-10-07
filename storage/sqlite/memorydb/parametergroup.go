package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readParameterGroup(row sqlcgen.MemorydbParameterGroup) (domain.ParameterGroup, error) {
	v := domain.ParameterGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "parametergroup", Name: row.Name}, Family: row.Family, Description: row.Description, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	if e = r.readParameter(&v); e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) ParameterGroup(k domain.Key) (domain.ParameterGroup, error) {
	row, e := r.q.GetParameterGroup(r.ctx, k.ARN())
	if e != nil {
		return domain.ParameterGroup{}, missing(e)
	}
	return r.readParameterGroup(row)
}
func (r reader) ParameterGroups(sc domain.Scope) ([]domain.ParameterGroup, error) {
	rows, e := r.q.ListParameterGroup(r.ctx, sqlcgen.ListParameterGroupParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ParameterGroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.readParameterGroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutParameterGroup(v domain.ParameterGroup) error {
	if e := w.q.PutParameterGroup(w.ctx, sqlcgen.PutParameterGroupParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, Family: v.Family, Description: v.Description, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return w.putParameter(v)
}
func (w writer) DeleteParameterGroup(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	if e := w.q.ClearParameter(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteParameterGroup(w.ctx, k.ARN())
}
