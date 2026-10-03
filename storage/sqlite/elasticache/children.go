package elasticache

import (
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) tags(k domain.Key) (map[string]string, error) {
	rows, e := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, row := range rows {
		out[row.TagKey] = row.TagValue
	}
	return out, nil
}
func (w writer) putTags(k domain.Key, v map[string]string) error {
	if e := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, name := range slices.Sorted(maps.Keys(v)) {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, TagKey: name, TagValue: v[name]}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) parameters(k domain.Key) (map[string]string, error) {
	rows, e := r.q.ListParameters(r.ctx, sqlcgen.ListParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, row := range rows {
		out[row.ParameterName] = row.ParameterValue
	}
	return out, nil
}
func (w writer) putParameters(k domain.Key, v map[string]string) error {
	if e := w.q.DeleteParameters(w.ctx, sqlcgen.DeleteParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, name := range slices.Sorted(maps.Keys(v)) {
		if e := w.q.PutParameter(w.ctx, sqlcgen.PutParameterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, ParameterName: name, ParameterValue: v[name]}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) nodes(k domain.Key) ([]engine.Node, error) {
	rows, e := r.q.ListNodes(r.ctx, sqlcgen.ListNodesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]engine.Node, 0, len(rows))
	for _, row := range rows {
		out = append(out, engine.Node{ID: row.NodeID, Shard: int32(row.Shard), Replica: int32(row.Replica), Endpoint: engine.Endpoint{Address: row.Address, Port: int32(row.Port)}})
	}
	return out, nil
}
func (w writer) putNodes(k domain.Key, v []engine.Node) error {
	if e := w.q.DeleteNodes(w.ctx, sqlcgen.DeleteNodesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for index, item := range v {
		if e := w.q.PutNode(w.ctx, sqlcgen.PutNodeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, NodeID: item.ID, Shard: int64(item.Shard), Replica: int64(item.Replica), Address: item.Endpoint.Address, Port: int64(item.Endpoint.Port), Ordinal: int64(index)}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) hashes(k domain.Key) ([]string, error) {
	rows, e := r.q.ListHashs(r.ctx, sqlcgen.ListHashsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.HexHash)
	}
	return out, nil
}
func (w writer) putHashes(k domain.Key, v []string) error {
	if e := w.q.DeleteHashs(w.ctx, sqlcgen.DeleteHashsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for index, item := range v {
		if e := w.q.PutHash(w.ctx, sqlcgen.PutHashParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, HexHash: item, Ordinal: int64(index)}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) members(k domain.Key) ([]string, error) {
	rows, e := r.q.ListMembers(r.ctx, sqlcgen.ListMembersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.UserID)
	}
	return out, nil
}
func (w writer) putMembers(k domain.Key, v []string) error {
	if e := w.q.DeleteMembers(w.ctx, sqlcgen.DeleteMembersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, item := range v {
		if e := w.q.PutMember(w.ctx, sqlcgen.PutMemberParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, UserID: item}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) subnets(k domain.Key) ([]domain.Subnet, error) {
	rows, e := r.q.ListSubnets(r.ctx, sqlcgen.ListSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Subnet, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Subnet{ID: row.SubnetID, VPCID: row.VpcID, AvailabilityZone: row.AvailabilityZone})
	}
	return out, nil
}
func (w writer) putSubnets(k domain.Key, v []domain.Subnet) error {
	if e := w.q.DeleteSubnets(w.ctx, sqlcgen.DeleteSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, item := range v {
		if e := w.q.PutSubnet(w.ctx, sqlcgen.PutSubnetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, SubnetID: item.ID, VpcID: item.VPCID, AvailabilityZone: item.AvailabilityZone}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) deleteChildren(k domain.Key) error {
	if e := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteParameters(w.ctx, sqlcgen.DeleteParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteNodes(w.ctx, sqlcgen.DeleteNodesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteHashs(w.ctx, sqlcgen.DeleteHashsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteMembers(w.ctx, sqlcgen.DeleteMembersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteSubnets(w.ctx, sqlcgen.DeleteSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	return nil
}
