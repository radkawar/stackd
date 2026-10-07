package rds

import (
	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func (r reader) SubnetGroup(k domain.Key) (domain.SubnetGroup, error) {
	row, e := r.q.GetSubnetGroup(r.ctx, sqlcgen.GetSubnetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.SubnetGroup{}, missing(e)
	}
	return r.subnetGroup(row)
}

func (r reader) SubnetGroups(scope domain.Scope) ([]domain.SubnetGroup, error) {
	rows, e := r.q.ListSubnetGroups(r.ctx, sqlcgen.ListSubnetGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.SubnetGroup, 0, len(rows))
	for _, row := range rows {

		v, e := r.subnetGroup(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)

	}
	return out, nil
}

func (r reader) subnetGroup(row sqlcgen.RdsSubnetGroup) (domain.SubnetGroup, error) {
	v := domain.SubnetGroup{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, ResourceID: row.ResourceID, Owner: domain.CloudFormationOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, Description: row.Description, VPCID: row.VpcID}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Subnets, e = r.subnets(v.Key)
	return v, e
}

func (w writer) PutSubnetGroup(v domain.SubnetGroup) error {
	k := v.Key
	if e := w.q.PutSubnetGroup(w.ctx, sqlcgen.PutSubnetGroupParams{Partition: k.Partition, ResourceID: v.ResourceID, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Description: v.Description, VpcID: v.VPCID}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	return w.putSubnets(k, v.Subnets)
}

func (w writer) DeleteSubnetGroup(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteSubnetGroup(w.ctx, sqlcgen.DeleteSubnetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
