package dynamodb

import (
	"encoding/json"

	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
)

func (r reader) ReplicaTables(groupID string) ([]domain.TableRecord, error) {
	rows, err := r.q.ListReplicaTables(r.ctx, groupID)
	if err != nil {
		return nil, err
	}
	return r.tables(rows)
}

func (r reader) ReplicaBootstrap(k domain.TableKey) (domain.ReplicaBootstrap, error) {
	row, err := r.q.GetReplicaBootstrap(r.ctx, sqlcgen.GetReplicaBootstrapParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TableName: k.Name})
	if err != nil {
		return domain.ReplicaBootstrap{}, missing(err)
	}
	return replicaBootstrapData(row)
}

func (r reader) ReplicaBootstraps(databaseID string) ([]domain.ReplicaBootstrap, error) {
	rows, err := r.q.ListReplicaBootstraps(r.ctx, databaseID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicaBootstrap, len(rows))
	for i, row := range rows {
		out[i], err = replicaBootstrapData(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func replicaBootstrapData(row sqlcgen.DynamodbReplicaBootstrap) (domain.ReplicaBootstrap, error) {
	out := domain.ReplicaBootstrap{
		Table:            domain.TableKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.TableName},
		Source:           domain.TableKey{Scope: domain.Scope{Partition: row.SourcePartition, AccountID: row.SourceAccountID, Region: row.SourceRegion}, Name: row.SourceTableName},
		SourceDatabaseID: row.SourceDatabaseID, SourcePhysicalName: row.SourcePhysicalName,
		SnapshotPhysicalName: row.SnapshotPhysicalName, Ready: row.Ready, Copied: row.Copied, Cursor: row.Cursor,
	}
	err := unmarshalFields(jsonReadField{row.KeySchema, &out.KeySchema}, jsonReadField{row.AttributeDefinitions, &out.AttributeDefinitions})
	return out, err
}

func (w writer) PutReplicaBootstrap(v domain.ReplicaBootstrap) error {
	params := sqlcgen.PutReplicaBootstrapParams{
		Partition: v.Table.Partition, AccountID: v.Table.AccountID, Region: v.Table.Region, TableName: v.Table.Name,
		SourcePartition: v.Source.Partition, SourceAccountID: v.Source.AccountID, SourceRegion: v.Source.Region, SourceTableName: v.Source.Name,
		SourceDatabaseID: v.SourceDatabaseID, SourcePhysicalName: v.SourcePhysicalName,
		SnapshotPhysicalName: v.SnapshotPhysicalName, Ready: v.Ready, Copied: v.Copied, Cursor: v.Cursor,
	}
	if err := marshalFields(jsonWriteField{&params.KeySchema, v.KeySchema}, jsonWriteField{&params.AttributeDefinitions, v.AttributeDefinitions}); err != nil {
		return err
	}
	return w.q.PutReplicaBootstrap(w.ctx, params)
}

func (w writer) DeleteReplicaBootstrap(k domain.TableKey) error {
	return w.q.DeleteReplicaBootstrap(w.ctx, sqlcgen.DeleteReplicaBootstrapParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, TableName: k.Name})
}

func (w writer) SnapshotReplicaVersions(target domain.TableKey, sourcePhysicalName string) error {
	if _, err := w.q.GetReplicaBootstrap(w.ctx, sqlcgen.GetReplicaBootstrapParams{Partition: target.Partition, AccountID: target.AccountID, Region: target.Region, TableName: target.Name}); err != nil {
		return missing(err)
	}
	if err := w.q.DeleteReplicaPinnedVersions(w.ctx, sqlcgen.DeleteReplicaPinnedVersionsParams{Partition: target.Partition, AccountID: target.AccountID, Region: target.Region, TableName: target.Name}); err != nil {
		return err
	}
	return w.q.SnapshotReplicaVersions(w.ctx, sqlcgen.SnapshotReplicaVersionsParams{Partition: target.Partition, AccountID: target.AccountID, Region: target.Region, TableName: target.Name, SourcePhysicalName: sourcePhysicalName})
}

func (w writer) InstallReplicaVersions(target domain.TableKey, targetPhysicalName string) error {
	if _, err := w.q.GetReplicaBootstrap(w.ctx, sqlcgen.GetReplicaBootstrapParams{Partition: target.Partition, AccountID: target.AccountID, Region: target.Region, TableName: target.Name}); err != nil {
		return missing(err)
	}
	if err := w.q.DeleteReplicaVersions(w.ctx, targetPhysicalName); err != nil {
		return err
	}
	return w.q.InstallReplicaVersions(w.ctx, sqlcgen.InstallReplicaVersionsParams{TargetPhysicalName: targetPhysicalName, Partition: target.Partition, AccountID: target.AccountID, Region: target.Region, TableName: target.Name})
}

func (r reader) ReplicaVersion(physicalName, keyID string) (int64, error) {
	return r.q.GetReplicaVersion(r.ctx, sqlcgen.GetReplicaVersionParams{PhysicalName: physicalName, KeyID: keyID})
}

func (w writer) PutReplicaVersion(physicalName, keyID string, version int64) error {
	return w.q.PutReplicaVersion(w.ctx, sqlcgen.PutReplicaVersionParams{PhysicalName: physicalName, KeyID: keyID, Version: version})
}

func (w writer) DeleteReplicaVersions(physicalName string) error {
	return w.q.DeleteReplicaVersions(w.ctx, physicalName)
}

func (r reader) ReplicaSequence(groupID string) (int64, error) {
	return r.q.GetReplicaSequence(r.ctx, groupID)
}

func (r reader) ReplicaChange(groupID string, sequence int64) (domain.ReplicaChange, error) {
	row, err := r.q.GetReplicaChange(r.ctx, sqlcgen.GetReplicaChangeParams{GroupID: groupID, Sequence: sequence})
	if err != nil {
		return domain.ReplicaChange{}, missing(err)
	}
	return replicaChangeData(row)
}

func (r reader) ReplicaChanges(groupID string, after int64, limit int) ([]domain.ReplicaChange, error) {
	rows, err := r.q.ListReplicaChanges(r.ctx, sqlcgen.ListReplicaChangesParams{GroupID: groupID, AfterSequence: after, RowLimit: rowLimit(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ReplicaChange, len(rows))
	for i, row := range rows {
		out[i], err = replicaChangeData(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func replicaChangeData(row sqlcgen.DynamodbReplicaChange) (domain.ReplicaChange, error) {
	out := domain.ReplicaChange{
		GroupID: row.GroupID, Sequence: row.Sequence, Version: row.Version, At: row.At.UTC(),
		Origin:             domain.TableKey{Scope: domain.Scope{Partition: row.OriginPartition, AccountID: row.OriginAccountID, Region: row.OriginRegion}, Name: row.OriginTableName},
		OriginPhysicalName: row.OriginPhysicalName, KeyID: row.KeyID,
	}
	if err := json.Unmarshal(row.KeyData, &out.Key); err != nil {
		return domain.ReplicaChange{}, err
	}
	if row.ItemData != nil {
		if err := json.Unmarshal(row.ItemData, &out.Item); err != nil {
			return domain.ReplicaChange{}, err
		}
	}
	return out, nil
}

func (w writer) AppendReplicaChanges(changes []domain.ReplicaChange) error {
	for _, v := range changes {
		params := sqlcgen.AppendReplicaChangeParams{
			GroupID: v.GroupID, Version: v.Version, At: v.At.UTC(), OriginPartition: v.Origin.Partition,
			OriginAccountID: v.Origin.AccountID, OriginRegion: v.Origin.Region, OriginTableName: v.Origin.Name,
			OriginPhysicalName: v.OriginPhysicalName, KeyID: v.KeyID,
		}
		var err error
		params.KeyData, err = json.Marshal(v.Key)
		if err != nil {
			return err
		}
		if v.Item != nil {
			params.ItemData, err = json.Marshal(v.Item)
			if err != nil {
				return err
			}
		}
		if err := w.q.AppendReplicaChange(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) TrimReplicaChanges(groupID string, throughSequence int64) error {
	if err := w.q.TrimReplicaChanges(w.ctx, sqlcgen.TrimReplicaChangesParams{GroupID: groupID, ThroughSequence: throughSequence}); err != nil {
		return err
	}
	return w.q.TrimReplicaVersions(w.ctx, groupID)
}
