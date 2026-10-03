package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readCluster(row sqlcgen.MemorydbCluster) (domain.Cluster, error) {
	v := domain.Cluster{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "cluster", Name: row.Name}, RuntimeID: row.RuntimeID, Status: row.Status, Operation: row.Operation, Description: row.Description, NodeType: row.NodeType, Engine: row.Engine, EngineVersion: row.EngineVersion, ACLName: row.AclName, ParameterGroup: row.ParameterGroup, RestoreSnapshot: row.RestoreSnapshot, Shards: int32(row.Shards), Replicas: int32(row.Replicas), TLSEnabled: row.TlsEnabled != 0, Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due)}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	if e = r.readNode(&v); e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) Cluster(k domain.Key) (domain.Cluster, error) {
	row, e := r.q.GetCluster(r.ctx, k.ARN())
	if e != nil {
		return domain.Cluster{}, missing(e)
	}
	return r.readCluster(row)
}
func (r reader) Clusters(sc domain.Scope) ([]domain.Cluster, error) {
	rows, e := r.q.ListCluster(r.ctx, sqlcgen.ListClusterParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Cluster, 0, len(rows))
	for _, row := range rows {
		v, e := r.readCluster(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) AllClusters() ([]domain.Cluster, error) {
	rows, e := r.q.AllCluster(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Cluster, 0, len(rows))
	for _, row := range rows {
		v, e := r.readCluster(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutCluster(v domain.Cluster) error {
	if e := w.q.PutCluster(w.ctx, sqlcgen.PutClusterParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, RuntimeID: v.RuntimeID, Status: v.Status, Operation: v.Operation, Description: v.Description, NodeType: v.NodeType, Engine: v.Engine, EngineVersion: v.EngineVersion, AclName: v.ACLName, ParameterGroup: v.ParameterGroup, RestoreSnapshot: v.RestoreSnapshot, Shards: int64(v.Shards), Replicas: int64(v.Replicas), TlsEnabled: bit(v.TLSEnabled), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due)}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return w.putNode(v)
}
func (w writer) DeleteCluster(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	if e := w.q.ClearNode(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteCluster(w.ctx, k.ARN())
}
