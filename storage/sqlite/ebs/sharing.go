package ebs

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) RegionalSnapshot(partition, region, id string) (domain.SnapshotRecord, error) {
	v, err := r.q.GetRegionalSnapshot(r.ctx, sqlcgen.GetRegionalSnapshotParams{Partition: partition, Region: region, ID: id})
	if err != nil {
		return domain.SnapshotRecord{}, missing(err)
	}
	return r.snapshot(v)
}

func (r reader) AvailableSnapshots(scope domain.Scope) ([]domain.SnapshotRecord, error) {
	return r.snapshotRows(r.q.ListAvailableSnapshots(r.ctx, sqlcgen.ListAvailableSnapshotsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}))
}

func (r reader) SnapshotPublicAccess(scope domain.Scope) (domain.SnapshotPublicAccess, error) {
	row, err := r.q.GetSnapshotPublicAccess(r.ctx, sqlcgen.GetSnapshotPublicAccessParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	return domain.SnapshotPublicAccess{Scope: scope, State: api.SnapshotBlockPublicAccessState(row.State), OwnerStackID: row.OwnerStackID, OwnerLogicalID: row.OwnerLogicalID, OwnerToken: row.OwnerToken}, missing(err)
}

func (w writer) PutSnapshotPublicAccess(v domain.SnapshotPublicAccess) error {
	return w.q.PutSnapshotPublicAccess(w.ctx, sqlcgen.PutSnapshotPublicAccessParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, State: string(v.State), OwnerStackID: v.OwnerStackID, OwnerLogicalID: v.OwnerLogicalID, OwnerToken: v.OwnerToken})
}

func (r reader) SharedTags(k domain.SharedTagsKey) (map[string]string, error) {
	snapshot := k.Snapshot
	rows, err := r.q.ListSharedTags(r.ctx, sqlcgen.ListSharedTagsParams{Partition: snapshot.Partition, AccountID: snapshot.AccountID, Region: snapshot.Region, SnapshotID: snapshot.ID, RecipientAccountID: k.AccountID})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(rows))
	for _, row := range rows {
		tags[row.Key] = row.Value
	}
	return tags, nil
}

func (w writer) PutSharedTags(k domain.SharedTagsKey, tags map[string]string) error {
	snapshot := k.Snapshot
	if err := w.q.DeleteSharedTags(w.ctx, sqlcgen.DeleteSharedTagsParams{Partition: snapshot.Partition, AccountID: snapshot.AccountID, Region: snapshot.Region, SnapshotID: snapshot.ID, RecipientAccountID: k.AccountID}); err != nil {
		return err
	}
	for key, value := range tags {
		if err := w.q.PutSharedTag(w.ctx, sqlcgen.PutSharedTagParams{Partition: snapshot.Partition, AccountID: snapshot.AccountID, Region: snapshot.Region, SnapshotID: snapshot.ID, RecipientAccountID: k.AccountID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) TagsForAccount(scope domain.Scope) ([]domain.SnapshotTag, error) {
	rows, err := r.q.ListAccountTags(r.ctx, sqlcgen.ListAccountTagsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	tags := make([]domain.SnapshotTag, len(rows))
	for i, row := range rows {
		tags[i] = domain.SnapshotTag{Snapshot: domain.SnapshotKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.SnapshotID}, Key: row.Key, Value: row.Value}
	}
	return tags, nil
}
