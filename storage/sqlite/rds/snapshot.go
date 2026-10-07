package rds

import (
	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func (r reader) Snapshot(k domain.Key) (domain.Snapshot, error) {
	row, e := r.q.GetSnapshot(r.ctx, sqlcgen.GetSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return domain.Snapshot{}, missing(e)
	}
	return r.snapshot(row)
}

func (r reader) Snapshots(scope domain.Scope) ([]domain.Snapshot, error) {
	rows, e := r.q.ListSnapshots(r.ctx, sqlcgen.ListSnapshotsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
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

func (r reader) snapshot(row sqlcgen.RdsSnapshot) (domain.Snapshot, error) {
	v := domain.Snapshot{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Kind: row.Kind, Name: row.Name}, Owner: domain.CloudFormationOwner{StackID: row.OwnerStackID, LogicalID: row.OwnerLogicalID, Token: row.OwnerToken}, Source: row.Source, SourceRuntimeID: row.SourceRuntimeID, RuntimeID: row.RuntimeID, Engine: row.Engine, EngineVersion: row.EngineVersion, DatabaseName: row.DatabaseName, Username: row.Username, Class: row.Class, Status: row.Status, Ciphertext: row.Ciphertext, Version: row.Version, Created: readTime(row.Created), Due: readTime(row.Due)}
	var e error
	v.Tags, e = r.tags(v.Key)
	if e != nil {
		return v, e
	}
	v.Parameters, _, e = r.parameters(v.Key)
	return v, e
}

func (w writer) PutSnapshot(v domain.Snapshot) error {
	k := v.Key
	if e := w.q.PutSnapshot(w.ctx, sqlcgen.PutSnapshotParams{Partition: k.Partition, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, Source: v.Source, SourceRuntimeID: v.SourceRuntimeID, RuntimeID: v.RuntimeID, Engine: v.Engine, EngineVersion: v.EngineVersion, DatabaseName: v.DatabaseName, Username: v.Username, Class: v.Class, Status: v.Status, Ciphertext: blob(v.Ciphertext), Version: v.Version, Created: timeValue(v.Created), Due: timeValue(v.Due)}); e != nil {
		return e
	}
	if e := w.putTags(k, v.Tags); e != nil {
		return e
	}
	return w.putParameters(k, v.Parameters, nil)
}

func (w writer) DeleteSnapshot(k domain.Key) error {
	if e := w.deleteChildren(k); e != nil {
		return e
	}
	return w.q.DeleteSnapshot(w.ctx, sqlcgen.DeleteSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
