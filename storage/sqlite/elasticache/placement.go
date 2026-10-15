package elasticache

import (
	"net/netip"
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) clientSubnets(k domain.Key) ([]string, error) {
	rows, e := r.q.ListClientSubnets(r.ctx, sqlcgen.ListClientSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.SubnetID)
	}
	return out, nil
}
func (w writer) putClientSubnets(k domain.Key, values []string) error {
	if e := w.q.DeleteClientSubnets(w.ctx, sqlcgen.DeleteClientSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for index, value := range values {
		if e := w.q.PutClientSubnet(w.ctx, sqlcgen.PutClientSubnetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Ordinal: int64(index), SubnetID: value}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) securityGroups(k domain.Key) ([]string, error) {
	rows, e := r.q.ListSecurityGroups(r.ctx, sqlcgen.ListSecurityGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.SecurityGroupID)
	}
	return out, nil
}
func (w writer) putSecurityGroups(k domain.Key, values []string) error {
	if e := w.q.DeleteSecurityGroups(w.ctx, sqlcgen.DeleteSecurityGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for index, value := range values {
		if e := w.q.PutSecurityGroup(w.ctx, sqlcgen.PutSecurityGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Ordinal: int64(index), SecurityGroupID: value}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) nodePlacements(k domain.Key) ([]domain.CacheNodePlacement, error) {
	rows, e := r.q.ListNodePlacements(r.ctx, sqlcgen.ListNodePlacementsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.CacheNodePlacement, 0, len(rows))
	for _, row := range rows {
		address, e := netip.ParseAddr(row.Address)
		if e != nil {
			return nil, e
		}
		gateway, e := netip.ParseAddr(row.Gateway)
		if e != nil {
			return nil, e
		}
		pool, e := netip.ParsePrefix(row.Pool)
		if e != nil {
			return nil, e
		}
		out = append(out, domain.CacheNodePlacement{NodeIndex: int(row.NodeIndex), InterfaceID: row.InterfaceID, SubnetID: row.SubnetID, AvailabilityZone: row.AvailabilityZone, NetworkID: row.NetworkID, Address: address, Gateway: gateway, Pool: pool, MAC: row.Mac})
	}
	return out, nil
}
func (w writer) putNodePlacements(k domain.Key, values []domain.CacheNodePlacement) error {
	if e := w.q.DeleteNodePlacements(w.ctx, sqlcgen.DeleteNodePlacementsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for index, value := range values {
		if e := w.q.PutNodePlacement(w.ctx, sqlcgen.PutNodePlacementParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Ordinal: int64(index), NodeIndex: int64(value.NodeIndex), InterfaceID: value.InterfaceID, SubnetID: value.SubnetID, AvailabilityZone: value.AvailabilityZone, NetworkID: value.NetworkID, Address: value.Address.String(), Gateway: value.Gateway.String(), Pool: value.Pool.String(), Mac: value.MAC}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) deletePlacementChildren(k domain.Key) error {
	if e := w.q.DeleteClientSubnets(w.ctx, sqlcgen.DeleteClientSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteSecurityGroups(w.ctx, sqlcgen.DeleteSecurityGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteNodePlacements(w.ctx, sqlcgen.DeleteNodePlacementsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	return nil
}
