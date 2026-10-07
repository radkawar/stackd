package ebs

import (
	"errors"
	"fmt"

	"stackd/internal/services/ec2"
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

// Claims are keyed by the scoped native identifier (vol-/snap- namespaces are
// disjoint) and are immutable for that incarnation; ordinary writes never clear them.
func (r reader) cloudFormationClaim(scope domain.Scope, id string) (ec2.CloudFormationOwner, error) {
	row, err := r.q.GetCloudFormationClaim(r.ctx, sqlcgen.GetCloudFormationClaimParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ResourceID: id})
	if errors.Is(missing(err), domain.ErrNotFound) {
		return ec2.CloudFormationOwner{}, nil
	}
	if err != nil {
		return ec2.CloudFormationOwner{}, err
	}
	return ec2.CloudFormationOwner{ResourceType: row.ResourceType, Owner: row.Owner}, nil
}
func (w writer) putCloudFormationClaim(scope domain.Scope, id string, owner ec2.CloudFormationOwner) error {
	if owner.Owner == "" {
		return nil
	}
	if err := w.q.PutCloudFormationClaim(w.ctx, sqlcgen.PutCloudFormationClaimParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ResourceID: id, ResourceType: owner.ResourceType, Owner: owner.Owner}); err != nil {
		return err
	}
	current, err := w.cloudFormationClaim(scope, id)
	if err != nil {
		return err
	}
	if current != owner {
		return fmt.Errorf("EBS private creation claim conflict")
	}
	return nil
}
func (r reader) CloudFormationCreation(k domain.CloudFormationCreationKey) (string, error) {
	id, err := r.q.GetCloudFormationCreation(r.ctx, sqlcgen.GetCloudFormationCreationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceType: k.ResourceType, Owner: k.Owner})
	return id, missing(err)
}
func (w writer) PutCloudFormationCreation(k domain.CloudFormationCreationKey, id string) error {
	if err := w.q.PutCloudFormationCreation(w.ctx, sqlcgen.PutCloudFormationCreationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceType: k.ResourceType, Owner: k.Owner, ResourceID: id}); err != nil {
		return err
	}
	prior, err := w.CloudFormationCreation(k)
	if err != nil {
		return err
	}
	if prior != id {
		return fmt.Errorf("EBS private creation receipt conflict")
	}
	return nil
}
