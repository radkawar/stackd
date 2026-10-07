package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readSubnetGroup(row sqlcgen.MemorydbSubnetGroup) (domain.SubnetGroup, error) {
	v := domain.SubnetGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "subnetgroup", Name: row.Name}, Description: row.Description, VPCID: row.VpcID, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	if e = r.readSubnet(&v); e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) SubnetGroup(k domain.Key) (domain.SubnetGroup, error) {
	row, e := r.q.GetSubnetGroup(r.ctx, k.ARN())
	if e != nil {
		return domain.SubnetGroup{}, missing(e)
	}
	return r.readSubnetGroup(row)
}
func (r reader) SubnetGroups(sc domain.Scope) ([]domain.SubnetGroup, error) {
	rows, e := r.q.ListSubnetGroup(r.ctx, sqlcgen.ListSubnetGroupParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.SubnetGroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.readSubnetGroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutSubnetGroup(v domain.SubnetGroup) error {
	if e := w.q.PutSubnetGroup(w.ctx, sqlcgen.PutSubnetGroupParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, Description: v.Description, VpcID: v.VPCID, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return w.putSubnet(v)
}
func (w writer) DeleteSubnetGroup(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	if e := w.q.ClearSubnet(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteSubnetGroup(w.ctx, k.ARN())
}
