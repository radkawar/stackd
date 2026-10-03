package ec2

import (
	"database/sql"
	"errors"
	"time"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func profileAssociation(row sqlcgen.Ec2InstanceProfileAssociation) domain.InstanceProfileAssociationRecord {
	return domain.InstanceProfileAssociationRecord{
		Key:        domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID},
		InstanceID: row.InstanceID, ProfileARN: row.ProfileArn, ProfileID: row.ProfileID,
		State: api.IamInstanceProfileAssociationState(row.State), Timestamp: row.Timestamp, NextActionAt: row.NextActionAt.Time,
		Credentials: domain.InstanceCredentialReferences{V1: row.CredentialIDV1, V2: row.CredentialIDV2},
	}
}
func (r reader) InstanceProfileAssociation(k domain.ResourceKey) (domain.InstanceProfileAssociationRecord, error) {
	row, err := r.q.GetInstanceProfileAssociation(r.ctx, sqlcgen.GetInstanceProfileAssociationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.InstanceProfileAssociationRecord{}, missing(err)
	}
	return profileAssociation(row), nil
}
func (r reader) InstanceProfileAssociations(scope domain.Scope) ([]domain.InstanceProfileAssociationRecord, error) {
	rows, err := r.q.ListInstanceProfileAssociations(r.ctx, sqlcgen.ListInstanceProfileAssociationsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return profileAssociationRows(rows), nil
}
func profileAssociationRows(rows []sqlcgen.Ec2InstanceProfileAssociation) []domain.InstanceProfileAssociationRecord {
	out := make([]domain.InstanceProfileAssociationRecord, len(rows))
	for i, row := range rows {
		out[i] = profileAssociation(row)
	}
	return out
}
func (r reader) PendingInstanceProfileAssociations(deadline time.Time) ([]domain.InstanceProfileAssociationRecord, error) {
	rows, err := r.q.PendingInstanceProfileAssociations(r.ctx, instanceTime(deadline))
	if err != nil {
		return nil, err
	}
	return profileAssociationRows(rows), nil
}
func (r reader) NextInstanceProfileAssociationDeadline() (time.Time, bool, error) {
	due, err := r.q.NextInstanceProfileAssociationDeadline(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	return due.Time, due.Valid, err
}
func (w writer) PutInstanceProfileAssociation(v domain.InstanceProfileAssociationRecord) error {
	return w.q.PutInstanceProfileAssociation(w.ctx, sqlcgen.PutInstanceProfileAssociationParams{
		Partition: v.Key.Scope.Partition, AccountID: v.Key.Scope.AccountID, Region: v.Key.Scope.Region, ResourceID: v.Key.ID,
		InstanceID: v.InstanceID, ProfileArn: v.ProfileARN, ProfileID: v.ProfileID, State: string(v.State), Timestamp: v.Timestamp.UTC(), NextActionAt: instanceTime(v.NextActionAt),
		CredentialIDV1: v.Credentials.V1,
		CredentialIDV2: v.Credentials.V2,
	})
}
func (w writer) DeleteInstanceProfileAssociation(k domain.ResourceKey) error {
	return deleted(w.q.DeleteInstanceProfileAssociation(w.ctx, sqlcgen.DeleteInstanceProfileAssociationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
