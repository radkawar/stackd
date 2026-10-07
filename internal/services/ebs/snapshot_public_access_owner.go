package ebs

import (
	"context"

	api "stackd/internal/awsapi/ec2"
)

// SnapshotPublicAccessOwner is a trusted consumer's private incarnation binding.
// It is not an IAM bypass, public API property, or a second setting catalog.
// An ordinary account setting command replaces the binding with its own intent.
// Intent is create, update, delete, observe, observe-deletion or recover-create.
// StackID and LogicalID are empty for a direct Cloud Control creation; Token
// still identifies that creation, and later direct mutations use ordinary IAM.
type SnapshotPublicAccessOwner struct {
	StackID, LogicalID, Token, Intent string
}

type snapshotPublicAccessOwnerKey struct{}

func WithSnapshotPublicAccessOwner(ctx context.Context, owner SnapshotPublicAccessOwner) context.Context {
	return context.WithValue(ctx, snapshotPublicAccessOwnerKey{}, owner)
}

func snapshotPublicAccessOwned(record SnapshotPublicAccess, owner SnapshotPublicAccessOwner) bool {
	return owner.Token != "" && record.OwnerToken == owner.Token && record.OwnerStackID == owner.StackID && record.OwnerLogicalID == owner.LogicalID
}

func admitSnapshotPublicAccessOwner(ctx context.Context, action string, current SnapshotPublicAccess, next api.SnapshotBlockPublicAccessState) (SnapshotPublicAccess, error) {
	owner, bound := ctx.Value(snapshotPublicAccessOwnerKey{}).(SnapshotPublicAccessOwner)
	if !bound {
		if action != "GetSnapshotBlockPublicAccessState" {
			current.OwnerStackID, current.OwnerLogicalID, current.OwnerToken = "", "", ""
		}
		current.State = next
		return current, nil
	}
	if owner.Token == "" {
		return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "A snapshot public access resource incarnation token is required.")
	}
	matched := snapshotPublicAccessOwned(current, owner)
	switch owner.Intent {
	case "recover-create", "observe", "observe-deletion":
		if action != "GetSnapshotBlockPublicAccessState" {
			return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "Snapshot public access observation cannot mutate its setting.")
		}
		if !matched {
			return SnapshotPublicAccess{}, ec2Failure("InvalidSnapshotBlockPublicAccessOwner.NotFound", "The snapshot public access setting is not owned by this resource incarnation.")
		}
	case "create":
		if action != "EnableSnapshotBlockPublicAccess" {
			return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "Snapshot public access creation requires EnableSnapshotBlockPublicAccess.")
		}
		if !matched && (current.OwnerToken != "" || current.State != "unblocked") {
			return SnapshotPublicAccess{}, ec2Failure("ResourceAlreadyExists", "The account already has a snapshot public access setting owned by another operation.")
		}
		current.OwnerStackID, current.OwnerLogicalID, current.OwnerToken = owner.StackID, owner.LogicalID, owner.Token
	case "update":
		if action != "EnableSnapshotBlockPublicAccess" {
			return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "Snapshot public access update requires EnableSnapshotBlockPublicAccess.")
		}
		if !matched {
			return SnapshotPublicAccess{}, ec2Failure("InvalidSnapshotBlockPublicAccessOwner.NotFound", "The snapshot public access setting is not owned by this resource incarnation.")
		}
	case "delete":
		if action != "DisableSnapshotBlockPublicAccess" {
			return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "Snapshot public access deletion requires DisableSnapshotBlockPublicAccess.")
		}
		if !matched {
			return SnapshotPublicAccess{}, ec2Failure("InvalidSnapshotBlockPublicAccessOwner.NotFound", "The snapshot public access setting is not owned by this resource incarnation.")
		}
		current.OwnerStackID, current.OwnerLogicalID, current.OwnerToken = "", "", ""
	default:
		return SnapshotPublicAccess{}, ec2Failure("InvalidParameterValue", "Unknown snapshot public access resource intent.")
	}
	current.State = next
	return current, nil
}
