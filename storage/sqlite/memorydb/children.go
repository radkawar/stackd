package memorydb

import (
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) tags(arn string) (map[string]string, error) {
	rows, e := r.q.ListTag(r.ctx, arn)
	if e != nil {
		return nil, e
	}
	out := make(map[string]string, len(rows))
	for _, v := range rows {
		out[v.TagKey] = v.TagValue
	}
	return out, nil
}
func (w writer) putTags(arn string, tags map[string]string) error {
	if e := w.q.ClearTag(w.ctx, arn); e != nil {
		return e
	}
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{OwnerArn: arn, TagKey: k, TagValue: tags[k]}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) readNode(v *domain.Cluster) error {
	rows, e := r.q.ListNode(r.ctx, v.Key.ARN())
	if e != nil {
		return e
	}
	v.Deployment.Nodes = make([]engine.Node, 0, len(rows))
	for _, n := range rows {
		node := engine.Node{ID: n.NodeID, Shard: int32(n.Shard), Replica: int32(n.Replica), Endpoint: engine.Endpoint{Address: n.Address, Port: int32(n.Port)}}
		v.Deployment.Nodes = append(v.Deployment.Nodes, node)
		if node.Shard == 0 && node.Replica == 0 {
			v.Deployment.Endpoint = node.Endpoint
		}
	}
	return nil
}
func (w writer) putNode(v domain.Cluster) error {
	if e := w.q.ClearNode(w.ctx, v.Key.ARN()); e != nil {
		return e
	}
	for _, n := range v.Deployment.Nodes {
		if e := w.q.PutNode(w.ctx, sqlcgen.PutNodeParams{OwnerArn: v.Key.ARN(), NodeID: n.ID, Shard: int64(n.Shard), Replica: int64(n.Replica), Address: n.Endpoint.Address, Port: int64(n.Endpoint.Port)}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) readPasswordHash(v *domain.User) error {
	rows, e := r.q.ListPasswordHash(r.ctx, v.Key.ARN())
	if e != nil {
		return e
	}
	v.PasswordHashes = make([]string, 0, len(rows))
	for _, n := range rows {
		v.PasswordHashes = append(v.PasswordHashes, n.PasswordHash)
	}
	return nil
}
func (w writer) putPasswordHash(v domain.User) error {
	if e := w.q.ClearPasswordHash(w.ctx, v.Key.ARN()); e != nil {
		return e
	}
	for _, hash := range v.PasswordHashes {
		if e := w.q.PutPasswordHash(w.ctx, sqlcgen.PutPasswordHashParams{OwnerArn: v.Key.ARN(), PasswordHash: hash}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) readACLUser(v *domain.ACL) error {
	rows, e := r.q.ListACLUser(r.ctx, v.Key.ARN())
	if e != nil {
		return e
	}
	v.Users = make([]string, 0, len(rows))
	for _, n := range rows {
		v.Users = append(v.Users, n.UserName)
	}
	return nil
}
func (w writer) putACLUser(v domain.ACL) error {
	if e := w.q.ClearACLUser(w.ctx, v.Key.ARN()); e != nil {
		return e
	}
	for _, name := range v.Users {
		if e := w.q.PutACLUser(w.ctx, sqlcgen.PutACLUserParams{OwnerArn: v.Key.ARN(), UserName: name}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) readParameter(v *domain.ParameterGroup) error {
	rows, e := r.q.ListParameter(r.ctx, v.Key.ARN())
	if e != nil {
		return e
	}
	v.Parameters = make(map[string]string, len(rows))
	for _, n := range rows {
		v.Parameters[n.ParameterName] = n.ParameterValue
	}
	return nil
}
func (w writer) putParameter(v domain.ParameterGroup) error {
	if e := w.q.ClearParameter(w.ctx, v.Key.ARN()); e != nil {
		return e
	}
	for _, name := range slices.Sorted(maps.Keys(v.Parameters)) {
		if e := w.q.PutParameter(w.ctx, sqlcgen.PutParameterParams{OwnerArn: v.Key.ARN(), ParameterName: name, ParameterValue: v.Parameters[name]}); e != nil {
			return e
		}
	}
	return nil
}
func (r reader) readSubnet(v *domain.SubnetGroup) error {
	rows, e := r.q.ListSubnet(r.ctx, v.Key.ARN())
	if e != nil {
		return e
	}
	v.Subnets = make([]domain.Subnet, 0, len(rows))
	for _, n := range rows {
		v.Subnets = append(v.Subnets, domain.Subnet{ID: n.SubnetID, VPCID: n.VpcID, AvailabilityZone: n.AvailabilityZone})
	}
	return nil
}
func (w writer) putSubnet(v domain.SubnetGroup) error {
	if e := w.q.ClearSubnet(w.ctx, v.Key.ARN()); e != nil {
		return e
	}
	for _, n := range v.Subnets {
		if e := w.q.PutSubnet(w.ctx, sqlcgen.PutSubnetParams{OwnerArn: v.Key.ARN(), SubnetID: n.ID, VpcID: n.VPCID, AvailabilityZone: n.AvailabilityZone}); e != nil {
			return e
		}
	}
	return nil
}
