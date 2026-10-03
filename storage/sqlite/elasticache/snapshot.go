package elasticache

import (
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite/elasticache/internal/sqlcgen"
)

func (r reader) Snapshot(k domain.Key) (domain.Snapshot, error) {
	row, e := r.q.GetSnapshot(r.ctx, sqlcgen.GetSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.Snapshot{}, missing(e)
	}
	return r.snapshot(row)
}
func (r reader) Snapshots(sc domain.Scope) ([]domain.Snapshot, error) {
	rows, e := r.q.ListSnapshots(r.ctx, sqlcgen.ListSnapshotsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Snapshot, 0, len(rows))
	for _, row := range rows {
		v, e := r.snapshot(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) AllSnapshots() ([]domain.Snapshot, error) {
	rows, e := r.q.AllSnapshots(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Snapshot, 0, len(rows))
	for _, row := range rows {
		v, e := r.snapshot(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) snapshot(row sqlcgen.ElasticacheSnapshot) (domain.Snapshot, error) {
	v := domain.Snapshot{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, SourceKind: row.SourceKind, Source: row.Source, SourceRuntimeID: row.SourceRuntimeID, RuntimeID: row.RuntimeID, CopySource: row.CopySource, Engine: row.Engine, EngineVersion: row.EngineVersion, NodeType: row.NodeType, Status: row.Status, Operation: row.Operation, MemoryBytes: row.MemoryBytes, Version: row.Version, Shards: int32(row.Shards), Replicas: int32(row.Replicas), ClusterMode: row.ClusterMode != 0, TLSEnabled: row.TlsEnabled != 0, Created: readTime(row.Created), Due: readTime(row.Due)}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, e = r.parameters(v.Key)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (w writer) PutSnapshot(v domain.Snapshot) error {
	k := v.Key
	if e := w.q.PutSnapshot(w.ctx, sqlcgen.PutSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, SourceKind: v.SourceKind, Source: v.Source, SourceRuntimeID: v.SourceRuntimeID, RuntimeID: v.RuntimeID, CopySource: v.CopySource, Engine: v.Engine, EngineVersion: v.EngineVersion, NodeType: v.NodeType, Status: v.Status, Operation: v.Operation, MemoryBytes: v.MemoryBytes, Version: v.Version, Shards: int64(v.Shards), Replicas: int64(v.Replicas), ClusterMode: bit(v.ClusterMode), TlsEnabled: bit(v.TLSEnabled), Created: timeValue(v.Created), Due: timeValue(v.Due)}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	if e := w.putParameters(k, v.Parameters); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteSnapshot(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteSnapshot(w.ctx, sqlcgen.DeleteSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
