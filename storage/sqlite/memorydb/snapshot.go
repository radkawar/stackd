package memorydb

import (
	domain "stackd/storage/memorydb"
	"stackd/storage/sqlite/memorydb/internal/sqlcgen"
)

func (r reader) readSnapshot(row sqlcgen.MemorydbSnapshot) (domain.Snapshot, error) {
	v := domain.Snapshot{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "snapshot", Name: row.Name}, RuntimeID: row.RuntimeID, SourceRuntimeID: row.SourceRuntimeID, Source: row.Source, CopySource: row.CopySource, Status: row.Status, Operation: row.Operation, Engine: row.Engine, EngineVersion: row.EngineVersion, NodeType: row.NodeType, ParameterGroup: row.ParameterGroup, ACLName: row.AclName, Shards: int32(row.Shards), Replicas: int32(row.Replicas), TLSEnabled: row.TlsEnabled != 0, Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due), CloudFormationOwner: row.CloudformationOwner}
	var e error
	v.Tags, e = r.tags(row.Arn)
	if e != nil {
		return v, e
	}
	return v, nil
}
func (r reader) Snapshot(k domain.Key) (domain.Snapshot, error) {
	row, e := r.q.GetSnapshot(r.ctx, k.ARN())
	if e != nil {
		return domain.Snapshot{}, missing(e)
	}
	return r.readSnapshot(row)
}
func (r reader) Snapshots(sc domain.Scope) ([]domain.Snapshot, error) {
	rows, e := r.q.ListSnapshot(r.ctx, sqlcgen.ListSnapshotParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Snapshot, 0, len(rows))
	for _, row := range rows {
		v, e := r.readSnapshot(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) AllSnapshots() ([]domain.Snapshot, error) {
	rows, e := r.q.AllSnapshot(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Snapshot, 0, len(rows))
	for _, row := range rows {
		v, e := r.readSnapshot(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutSnapshot(v domain.Snapshot) error {
	if e := w.q.PutSnapshot(w.ctx, sqlcgen.PutSnapshotParams{Arn: v.Key.ARN(), Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, RuntimeID: v.RuntimeID, SourceRuntimeID: v.SourceRuntimeID, Source: v.Source, CopySource: v.CopySource, Status: v.Status, Operation: v.Operation, Engine: v.Engine, EngineVersion: v.EngineVersion, NodeType: v.NodeType, ParameterGroup: v.ParameterGroup, AclName: v.ACLName, Shards: int64(v.Shards), Replicas: int64(v.Replicas), TlsEnabled: bit(v.TLSEnabled), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due), CloudformationOwner: v.CloudFormationOwner}); e != nil {
		return e
	}
	if e := w.putTags(v.Key.ARN(), v.Tags); e != nil {
		return e
	}
	return nil
}
func (w writer) DeleteSnapshot(k domain.Key) error {
	if e := w.q.ClearTag(w.ctx, k.ARN()); e != nil {
		return e
	}
	return w.q.DeleteSnapshot(w.ctx, k.ARN())
}
