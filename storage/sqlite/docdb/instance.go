package docdb

import (
	domain "stackd/storage/docdb"
	"stackd/storage/sqlite/docdb/internal/sqlcgen"
)

func (r reader) Instance(k domain.Key) (domain.Instance, error) {
	row, e := r.q.GetInstance(r.ctx, sqlcgen.GetInstanceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.Instance{}, missing(e)
	}
	return r.instance(row)
}
func (r reader) Instances() ([]domain.Instance, error) {
	rows, e := r.q.ListInstances(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Instance, 0, len(rows))
	for _, row := range rows {
		v, e := r.instance(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) instance(row sqlcgen.DocdbInstance) (domain.Instance, error) {
	v := domain.Instance{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "db", Name: row.Name}, Owner: domain.CloudFormationOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, Cluster: row.Cluster, Class: row.Class, RuntimeID: row.RuntimeID, Status: row.Status, Created: readTime(row.Created)}
	var e error
	v.Tags, e = r.tags(v.Key)
	return v, e
}
func (w writer) PutInstance(v domain.Instance) error {
	k := v.Key
	if e := w.q.PutInstance(w.ctx, sqlcgen.PutInstanceParams{Partition: k.Partition, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Cluster: v.Cluster, Class: v.Class, RuntimeID: v.RuntimeID, Status: v.Status, Created: timeValue(v.Created)}); e != nil {
		return e
	}
	return w.putTags(k, v.Tags)
}
func (w writer) DeleteInstance(k domain.Key) error {
	if e := w.deleteTags(k); e != nil {
		return e
	}
	return w.q.DeleteInstance(w.ctx, sqlcgen.DeleteInstanceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
