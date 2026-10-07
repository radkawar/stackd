package ec2

import (
	"context"
	"errors"
	"strings"
)

type relationOwnerKey struct{}
type relationOwner struct{ resourceType, slot, owner, deletingID string }

// WithRelationOwner carries recovery identity, not authority. Every native
// command still authorizes its actual resources under the current caller.
func WithRelationOwner(ctx context.Context, resourceType, slot, owner string) context.Context {
	return context.WithValue(ctx, relationOwnerKey{}, relationOwner{resourceType: resourceType, slot: slot, owner: owner})
}

func WithRelationDeletion(ctx context.Context, resourceType, slot, owner, id string) context.Context {
	return context.WithValue(ctx, relationOwnerKey{}, relationOwner{resourceType: resourceType, slot: slot, owner: owner, deletingID: id})
}

func relationAction(resourceType, slot string) string {
	return "CloudFormationRelation/" + resourceType + "/" + slot
}

// relationAdmission uses the existing private native creation owner records.
// The token receipt is immutable; the empty-token row is the current slot owner
// and is invalidated by direct EC2 effects, including identical replacements.
// Public resource tags play no part in admission.
func relationAdmission(ctx context.Context, tx Transaction, kind, slot, id string) error {
	resourceType := "AWS::EC2::" + kind
	action := relationAction(resourceType, slot)
	owner, marked := ctx.Value(relationOwnerKey{}).(relationOwner)
	current := NetworkOwnerCreationRecord{Key: NetworkCreationKey{Scope: scopeFor(ctx), Action: action}, ResourceID: id}
	if !marked || owner.deletingID != "" {
		previous, err := tx.NetworkOwnerCreation(current.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if marked && (owner.resourceType != resourceType || owner.slot != slot || err != nil || previous.Fingerprint != owner.owner || previous.ResourceID != owner.deletingID) {
			return failure("IncorrectState", "The EC2 relation is not the current admitted incarnation.")
		}
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return tx.PutNetworkOwnerCreation(current)
	}
	if marked {
		if owner.resourceType != resourceType || owner.slot != slot || owner.owner == "" {
			return failure("IncorrectState", "The EC2 relation creation identity does not match its native effect.")
		}
		receipt := NetworkOwnerCreationRecord{Key: NetworkCreationKey{Scope: scopeFor(ctx), Action: relationAction(resourceType, ""), Token: owner.owner}, ResourceID: id, Fingerprint: slot}
		previous, err := tx.NetworkOwnerCreation(receipt.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		// Gateway migration changes its parent slot in-place while retaining the
		// VPC-based identifier. The first admission stays immutable; each native
		// attach/detach still updates the exact current-slot owner atomically.
		if err == nil && (previous.ResourceID != id || (previous.Fingerprint != slot && kind != "VPCGatewayAttachment")) {
			return creationMismatch()
		}
		if errors.Is(err, ErrNotFound) {
			if err := tx.PutNetworkOwnerCreation(receipt); err != nil {
				return err
			}
		}
		current.Fingerprint = owner.owner
	}
	return tx.PutNetworkOwnerCreation(current)
}

// RelationCreation is private deployment recovery, not public tag discovery.
// Its observation has the same current IAM requirement as the native describe
// operation; adapters additionally observe the exact parent and live edge.
func (s *Service) RelationCreation(ctx context.Context, resourceType, slot, owner string) (id string, current bool, err error) {
	action := ""
	switch resourceType {
	case "AWS::EC2::SubnetRouteTableAssociation", "AWS::EC2::Route":
		action = "DescribeRouteTables"
	case "AWS::EC2::NetworkAclEntry", "AWS::EC2::SubnetNetworkAclAssociation":
		action = "DescribeNetworkAcls"
	case "AWS::EC2::VPCDHCPOptionsAssociation":
		action = "DescribeVpcs"
	case "AWS::EC2::VPCGatewayAttachment":
		action = "DescribeInternetGateways"
	case "AWS::EC2::EIPAssociation":
		action = "DescribeAddresses"
	case "AWS::EC2::VolumeAttachment":
		action = "DescribeVolumes"
	default:
		return "", false, failure("InvalidParameterValue", "Unsupported EC2 relation owner.")
	}
	if err = s.authorize(ctx, action, "", "*", nil); err != nil {
		return
	}
	if resourceType == "AWS::EC2::VolumeAttachment" {
		if err = s.authorize(ctx, "DescribeInstances", "", "*", nil); err != nil {
			return
		}
	}
	err = s.repository.View(ctx, func(r Reader) error {
		key := NetworkCreationKey{Scope: scopeFor(ctx), Action: relationAction(resourceType, ""), Token: owner}
		receipt, e := r.NetworkOwnerCreation(key)
		if e != nil {
			return e
		}
		id = receipt.ResourceID
		if slot != "" && slot != receipt.Fingerprint && resourceType != "AWS::EC2::VPCGatewayAttachment" {
			return failure("IncorrectState", "The native creation receipt belongs to another EC2 relation slot.")
		}
		if slot == "" {
			slot = receipt.Fingerprint
		}
		key.Action = relationAction(resourceType, slot)
		key.Token = ""
		live, e := r.NetworkOwnerCreation(key)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		current = live.Fingerprint == owner && live.ResourceID == id
		if current && resourceType == "AWS::EC2::VolumeAttachment" {
			parts := strings.Split(slot, "|")
			if len(parts) != 2 {
				return failure("IncorrectState", "Invalid native volume attachment slot.")
			}
			instance, e := r.Instance(ResourceKey{Scope: scopeFor(ctx), ID: parts[1]})
			if errors.Is(e, ErrNotFound) {
				current = false
				return nil
			}
			if e != nil {
				return e
			}
			current = false
			for _, mapping := range instance.Data.BlockDeviceMappings {
				if mapping.Ebs != nil && str(mapping.Ebs.VolumeId) == parts[0] && str(mapping.Ebs.Status) != "detached" && str(mapping.Ebs.Status) != "detaching" {
					current = true
					break
				}
			}
		}
		return nil
	})
	return
}
