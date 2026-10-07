package eks

import (
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func creationRecord(v sqlcgen.EksCloudformationCreation) domain.CloudFormationCreation {
	return domain.CloudFormationCreation{Key: domain.CloudFormationCreationKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ResourceType: v.ResourceType, Owner: v.Owner}, ClusterName: v.ClusterName, NativeName: v.NativeName, NativeID: v.NativeID, PhysicalID: v.PhysicalID, ARN: v.Arn}
}
func (r reader) CloudFormationCreation(key domain.CloudFormationCreationKey) (domain.CloudFormationCreation, error) {
	row, err := r.q.GetCloudFormationCreation(r.ctx, sqlcgen.GetCloudFormationCreationParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ResourceType: key.ResourceType, Owner: key.Owner})
	if err != nil {
		return domain.CloudFormationCreation{}, missing(err)
	}
	return creationRecord(row), nil
}
func (r reader) CloudFormationCreations(scope domain.Scope) ([]domain.CloudFormationCreation, error) {
	rows, err := r.q.ListCloudFormationCreations(r.ctx, sqlcgen.ListCloudFormationCreationsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CloudFormationCreation, len(rows))
	for i, row := range rows {
		out[i] = creationRecord(row)
	}
	return out, nil
}
func (w writer) PutCloudFormationCreation(row domain.CloudFormationCreation) error {
	return w.q.PutCloudFormationCreation(w.ctx, sqlcgen.PutCloudFormationCreationParams{Partition: row.Key.Partition, AccountID: row.Key.AccountID, Region: row.Key.Region, ResourceType: row.Key.ResourceType, Owner: row.Key.Owner, ClusterName: row.ClusterName, NativeName: row.NativeName, NativeID: row.NativeID, PhysicalID: row.PhysicalID, Arn: row.ARN})
}
