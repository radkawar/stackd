package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) SubnetGroup(k domain.Key) (domain.SubnetGroup, error) {
	row, e := r.q.GetSubnetGroup(r.ctx, sqlcgen.GetSubnetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.SubnetGroup{}, missing(e)
	}
	return r.subnetgroup(row)
}
func (r reader) SubnetGroups(sc domain.Scope) ([]domain.SubnetGroup, error) {
	rows, e := r.q.ListSubnetGroups(r.ctx, sqlcgen.ListSubnetGroupsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.SubnetGroup, 0, len(rows))
	for _, row := range rows {
		v, e := r.subnetgroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) subnetgroup(row sqlcgen.ElasticacheSubnetGroup) (domain.SubnetGroup, error) {
	v := domain.SubnetGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Description: row.Description, VPCID: row.VpcID, CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Subnets, e = r.subnets(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutSubnetGroup(v domain.SubnetGroup) error {
	k := v.Key
	if e := w.q.PutSubnetGroup(w.ctx, sqlcgen.PutSubnetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Description: v.Description, VpcID: v.VPCID, CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putSubnets(k, v.Subnets); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteSubnetGroup(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteSubnetGroup(w.ctx, sqlcgen.DeleteSubnetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
