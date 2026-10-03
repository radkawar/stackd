package docdb

import (
	engine "stackd/engine/docdb"
	domain "stackd/storage/docdb"
	"stackd/storage/sqlite/docdb/internal/sqlcgen"
)

func (r reader) Cluster(k domain.Key) (domain.Cluster, error) {
	row, e := r.q.GetCluster(r.ctx, sqlcgen.GetClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.Cluster{}, missing(e)
	}
	return r.cluster(row)
}
func (r reader) Clusters() ([]domain.Cluster, error) {
	rows, e := r.q.ListClusters(r.ctx)
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
func (r reader) cluster(row sqlcgen.DocdbCluster) (domain.Cluster, error) {
	v := domain.Cluster{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "cluster", Name: row.Name}, RuntimeID: row.RuntimeID, Username: row.Username, EngineVersion: row.EngineVersion, Status: row.Status, Operation: row.Operation, RestoreSnapshot: row.RestoreSnapshot, Ciphertext: row.Ciphertext, PendingCiphertext: row.PendingCiphertext, RequestedPort: int32(row.RequestedPort), Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due), DeletionProtection: row.DeletionProtection != 0, Endpoint: engine.Endpoint{Address: row.Address, Port: int32(row.Port), ReplicaSet: row.ReplicaSet, CA: row.Ca}}
	var e error
	v.Tags, e = r.tags(v.Key)
	return v, e
}
func (w writer) PutCluster(v domain.Cluster) error {
	k := v.Key
	if e := w.q.PutCluster(w.ctx, sqlcgen.PutClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, RuntimeID: v.RuntimeID, Username: v.Username, EngineVersion: v.EngineVersion, Status: v.Status, Operation: v.Operation, RestoreSnapshot: v.RestoreSnapshot, Ciphertext: blob(v.Ciphertext), PendingCiphertext: blob(v.PendingCiphertext), RequestedPort: int64(v.RequestedPort), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due), DeletionProtection: bit(v.DeletionProtection), Address: v.Endpoint.Address, Port: int64(v.Endpoint.Port), ReplicaSet: v.Endpoint.ReplicaSet, Ca: blob(v.Endpoint.CA)}); e != nil {
		return e
	}
	return w.putTags(k, v.Tags)
}
func (w writer) DeleteCluster(k domain.Key) error {
	if e := w.deleteTags(k); e != nil {
		return e
	}
	return w.q.DeleteCluster(w.ctx, sqlcgen.DeleteClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
