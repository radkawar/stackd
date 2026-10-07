package docdb

import (
	domain "stackd/storage/docdb"
	"stackd/storage/sqlite/docdb/internal/sqlcgen"
)

func (r reader) Snapshot(k domain.Key) (domain.Snapshot, error) {
	row, e := r.q.GetSnapshot(r.ctx, sqlcgen.GetSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.Snapshot{}, missing(e)
	}
	return r.snapshot(row)
}
func (r reader) Snapshots() ([]domain.Snapshot, error) {
	rows, e := r.q.ListSnapshots(r.ctx)
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
func (r reader) snapshot(row sqlcgen.DocdbSnapshot) (domain.Snapshot, error) {
	v := domain.Snapshot{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: "cluster-snapshot", Name: row.Name}, Owner: domain.CloudFormationOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, Source: row.Source, SourceRuntimeID: row.SourceRuntimeID, RuntimeID: row.RuntimeID, Username: row.Username, EngineVersion: row.EngineVersion, Status: row.Status, Operation: row.Operation, Ciphertext: row.Ciphertext, Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due)}
	var e error
	v.Tags, e = r.tags(v.Key)
	return v, e
}
func (w writer) PutSnapshot(v domain.Snapshot) error {
	k := v.Key
	if e := w.q.PutSnapshot(w.ctx, sqlcgen.PutSnapshotParams{Partition: k.Partition, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Source: v.Source, SourceRuntimeID: v.SourceRuntimeID, RuntimeID: v.RuntimeID, Username: v.Username, EngineVersion: v.EngineVersion, Status: v.Status, Operation: v.Operation, Ciphertext: blob(v.Ciphertext), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due)}); e != nil {
		return e
	}
	return w.putTags(k, v.Tags)
}
func (w writer) DeleteSnapshot(k domain.Key) error {
	if e := w.deleteTags(k); e != nil {
		return e
	}
	return w.q.DeleteSnapshot(w.ctx, sqlcgen.DeleteSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
