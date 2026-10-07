package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) Cluster(k domain.Key) (domain.Cluster, error) {
	row, e := r.q.GetCluster(r.ctx, sqlcgen.GetClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.Cluster{}, missing(e)
	}
	return r.cluster(row)
}
func (r reader) Clusters(sc domain.Scope) ([]domain.Cluster, error) {
	rows, e := r.q.ListClusters(r.ctx, sqlcgen.ListClustersParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Cluster, 0, len(rows))
	for _, row := range rows {
		v, e := r.cluster(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) AllClusters() ([]domain.Cluster, error) {
	rows, e := r.q.AllClusters(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Cluster, 0, len(rows))
	for _, row := range rows {
		v, e := r.cluster(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) cluster(row sqlcgen.ElasticacheCluster) (domain.Cluster, error) {
	v := domain.Cluster{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Engine: row.Engine, EngineVersion: row.EngineVersion, NodeType: row.NodeType, Description: row.Description, ParameterGroup: row.ParameterGroup, UserGroup: row.UserGroup, RuntimeID: row.RuntimeID, Status: row.Status, Operation: row.Operation, RestoreSnapshot: row.RestoreSnapshot, MemoryBytes: row.MemoryBytes, Version: row.Version, Shards: int32(row.Shards), Replicas: int32(row.Replicas), ClusterMode: row.ClusterMode != 0, TLSEnabled: row.TlsEnabled != 0, Created: readTime(row.Created), Due: readTime(row.Due), CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, e = r.parameters(v.Key)
	if e != nil {
		return v, e
	}
	v.Nodes, e = r.nodes(v.Key)
	if e != nil {
		return v, e
	}
	v.AuthHashes, e = r.hashes(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutCluster(v domain.Cluster) error {
	k := v.Key
	if e := w.q.PutCluster(w.ctx, sqlcgen.PutClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Engine: v.Engine, EngineVersion: v.EngineVersion, NodeType: v.NodeType, Description: v.Description, ParameterGroup: v.ParameterGroup, UserGroup: v.UserGroup, RuntimeID: v.RuntimeID, Status: v.Status, Operation: v.Operation, RestoreSnapshot: v.RestoreSnapshot, MemoryBytes: v.MemoryBytes, Version: v.Version, Shards: int64(v.Shards), Replicas: int64(v.Replicas), ClusterMode: bit(v.ClusterMode), TlsEnabled: bit(v.TLSEnabled), Created: timeValue(v.Created), Due: timeValue(v.Due), CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putParameters(k, v.Parameters); e != nil {
		return e
	}
	if e := w.putNodes(k, v.Nodes); e != nil {
		return e
	}
	if e := w.putHashes(k, v.AuthHashes); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteCluster(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteCluster(w.ctx, sqlcgen.DeleteClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
