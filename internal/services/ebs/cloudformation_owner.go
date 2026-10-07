package ebs

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

// CloudFormationCreationKey names an immutable native admission receipt.
type CloudFormationCreationKey struct {
	Scope
	ResourceType, Owner string
}

func creationKey(scope Scope, owner ec2.CloudFormationOwner) CloudFormationCreationKey {
	return CloudFormationCreationKey{Scope: scope, ResourceType: owner.ResourceType, Owner: owner.Owner}
}
func ownershipFailure() error {
	return ec2Failure("IncorrectState", "The EBS resource is not owned by this CloudFormation resource incarnation.")
}

// volumeMutationFence admits only the exact standalone Volume incarnation.
// Standalone EBS commands bypass EC2's instance fence, so any other trusted
// intent, including AWS::EC2::Instance, is rejected after IAM and DryRun.
func volumeMutationFence(ctx context.Context, v VolumeRecord) error {
	owner, target, create, present := ec2.CloudFormationIntent(ctx)
	if !present {
		return nil
	}
	if create || owner.ResourceType != "AWS::EC2::Volume" || target != v.Key.ID || owner.Owner == "" || owner != v.CloudFormationOwner {
		return ownershipFailure()
	}
	return nil
}

// Creation is admitted only with a newly allocated native row, never by tags or
// adoption of an ordinary client's idempotent replay.
func admitVolumeOwner(tx Transaction, v *VolumeRecord, replay bool) error {
	owner, _, create, present := ec2.CloudFormationIntent(tx.Context())
	if !present {
		return nil
	}
	if !create || owner.ResourceType != "AWS::EC2::Volume" || owner.Owner == "" {
		return ownershipFailure()
	}
	key := creationKey(v.Key.Scope, owner)
	prior, err := tx.CloudFormationCreation(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if replay {
		if err != nil || prior != v.Key.ID || v.CloudFormationOwner != owner {
			return ownershipFailure()
		}
		return nil
	}
	if err == nil {
		return ec2Failure("IdempotentParameterMismatch", "This CloudFormation incarnation already admitted an EBS volume.")
	}
	v.CloudFormationOwner = owner
	return tx.PutCloudFormationCreation(key, v.Key.ID)
}

func (s *Service) authorizeCloudFormationObservation(ctx context.Context, resourceType string) error {
	switch resourceType {
	case "AWS::EC2::Volume":
		return s.authorizeVolume(ctx, "DescribeVolumes", VolumeRecord{Key: VolumeKey{Scope: scopeFor(ctx), ID: "*"}}, nil)
	case "AWS::EC2::VolumeDeletionSnapshot":
		return s.authorize(ctx, "ec2", "DescribeSnapshots", SnapshotRecord{Key: SnapshotKey{Scope: scopeFor(ctx), ID: "*"}}, nil)
	default:
		return ec2Failure("InvalidParameterValue", "Unsupported EBS CloudFormation owner.")
	}
}
func cloudFormationCurrent(r Reader, owner ec2.CloudFormationOwner, id string) error {
	switch owner.ResourceType {
	case "AWS::EC2::Volume":
		v, err := r.Volume(VolumeKey{Scope: scopeFor(r.Context()), ID: id})
		if err != nil {
			return err
		}
		if v.CloudFormationOwner != owner {
			return ownershipFailure()
		}
	case "AWS::EC2::VolumeDeletionSnapshot":
		v, err := r.Snapshot(SnapshotKey{Scope: scopeFor(r.Context()), ID: id})
		if err != nil {
			return err
		}
		if v.Deleted || v.CloudFormationOwner != owner {
			return ownershipFailure()
		}
	}
	return nil
}
func (s *Service) CloudFormationCreation(ctx context.Context, resourceType, owner string) (id string, err error) {
	if err = s.authorizeCloudFormationObservation(ctx, resourceType); err != nil {
		return
	}
	if owner == "" {
		return "", ownershipFailure()
	}
	claim := ec2.CloudFormationOwner{ResourceType: resourceType, Owner: owner}
	err = s.repository.View(ctx, func(r Reader) error {
		var e error
		id, e = r.CloudFormationCreation(creationKey(scopeFor(r.Context()), claim))
		if e != nil {
			return e
		}
		if resourceType == "AWS::EC2::Volume" {
			v, e := r.Volume(VolumeKey{Scope: scopeFor(r.Context()), ID: id})
			if e != nil {
				return ownershipFailure()
			}
			if v.Status == api.VolumeStateDeleted || v.Status == api.VolumeStateDeleting {
				return ownershipFailure()
			}
		}
		if e = cloudFormationCurrent(r, claim, id); errors.Is(e, ErrNotFound) {
			return ownershipFailure()
		}
		return e
	})
	if errors.Is(err, ErrNotFound) {
		err = ec2.ErrNotFound
	}
	return
}
func (s *Service) CloudFormationOwned(ctx context.Context, resourceType, owner, id string) error {
	if err := s.authorizeCloudFormationObservation(ctx, resourceType); err != nil {
		return err
	}
	if owner == "" {
		return ownershipFailure()
	}
	return s.repository.View(ctx, func(r Reader) error {
		return cloudFormationCurrent(r, ec2.CloudFormationOwner{ResourceType: resourceType, Owner: owner}, id)
	})
}

func deletionSnapshotFence(tx Transaction, source VolumeRecord) error {
	owner, _, create, present := ec2.CloudFormationIntent(tx.Context())
	if !present {
		return nil
	}
	if owner.ResourceType == "AWS::EC2::Volume" {
		return volumeMutationFence(tx.Context(), source)
	}
	if !create || owner.ResourceType != "AWS::EC2::VolumeDeletionSnapshot" || owner.Owner == "" || source.CloudFormationOwner != (ec2.CloudFormationOwner{ResourceType: "AWS::EC2::Volume", Owner: owner.Owner}) {
		return ownershipFailure()
	}
	_, err := tx.CloudFormationCreation(creationKey(source.Key.Scope, owner))
	if err == nil {
		return ec2Failure("IdempotentParameterMismatch", "This volume incarnation already admitted a deletion snapshot.")
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

func admitDeletionSnapshotOwner(tx Transaction, snapshot *SnapshotRecord) error {
	owner, _, _, present := ec2.CloudFormationIntent(tx.Context())
	if !present || owner.ResourceType != "AWS::EC2::VolumeDeletionSnapshot" {
		return nil
	}
	snapshot.CloudFormationOwner = owner
	if err := tx.PutCloudFormationCreation(creationKey(snapshot.Key.Scope, owner), snapshot.Key.ID); err != nil {
		return err
	}
	return tx.PutSnapshot(*snapshot)
}
