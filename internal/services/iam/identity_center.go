package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"stackd/internal/authorization"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
)

// IdentityCenterPolicyReference resolves an existing customer policy in the
// target account. Identity Center does not copy or create those policy documents.
type IdentityCenterPolicyReference struct{ Name, Path string }

// IdentityCenterRoleSpec is a trusted, already-authorized service command. The
// Identity Center owner validates account membership and permission-set ownership.
// IAM remains the authority for role incarnations, policy references and limits.
type IdentityCenterRoleSpec struct {
	Scope
	Region, InstanceARN, PermissionSetARN, Name, InlinePolicy string
	ManagedPolicies                                           []string
	CustomerManagedPolicies                                   []IdentityCenterPolicyReference
	BoundaryARN                                               string
	Boundary                                                  IdentityCenterPolicyReference
	Duration                                                  time.Duration
}

// IdentityCenterRoleRef identifies the exact owned role incarnation. Names and
// public tags alone never confer permission to replace or remove an IAM role.
type IdentityCenterRoleRef struct {
	Scope
	InstanceARN, PermissionSetARN, ARN, ID, Name string
}

// ProvisionIdentityCenterRole atomically reconciles the reserved role and its
// policies without impersonating an account root or requiring public IAM rights.
// https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html
func (s *Service) ProvisionIdentityCenterRole(ctx context.Context, spec IdentityCenterRoleSpec) (Role, error) {
	var result Role
	if err := validateName(spec.Name, "PermissionSetName", 32); err != nil {
		return result, err
	}
	if spec.Duration < time.Hour || spec.Duration > 12*time.Hour || spec.Duration%time.Second != 0 {
		return result, invalid("Session duration must be between one and twelve hours in whole seconds.")
	}
	instanceID, ok := strings.CutPrefix(spec.InstanceARN, "arn:"+spec.Partition+":sso:::instance/")
	if !ok || instanceID == "" || strings.Contains(instanceID, "/") || !strings.HasPrefix(spec.PermissionSetARN, "arn:"+spec.Partition+":sso:::permissionSet/"+instanceID+"/") || spec.Region == "" || spec.AccountID == "" {
		return result, invalid("The Identity Center role scope and ownership must identify an instance and permission set.")
	}
	path := "/aws-reserved/sso.amazonaws.com/"
	if spec.Region != "us-east-1" {
		path += spec.Region + "/"
	}
	if _, err := validPath(path); err != nil {
		return result, err
	}
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sso.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, spec.InstanceARN)
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "sso.amazonaws.com", SourceARN: spec.InstanceARN, Type: "AWSService"})
	err := s.repository.Attempt(ctx, func(tx WriteTx) error {
		a, err := loadAccount(tx, spec.Scope)
		if err != nil {
			return err
		}
		a.currentTime = s.clock.Now().UTC()
		var current *Role
		for _, r := range a.roles {
			if r.IdentityCenterInstanceARN != spec.InstanceARN || r.IdentityCenterPermissionSetARN != spec.PermissionSetARN {
				continue
			}
			if current != nil || r.Path != path || !strings.HasPrefix(r.RoleName, "AWSReservedSSO_"+spec.Name+"_") || r.ServiceLinkedService != "" {
				return conflict("The reserved role does not uniquely match its Identity Center owner.")
			}
			current = r
		}
		if current == nil {
			var suffix [8]byte
			if _, err := rand.Read(suffix[:]); err != nil {
				return err
			}
			name := "AWSReservedSSO_" + spec.Name + "_" + hex.EncodeToString(suffix[:])
			metadata := awsctx.Metadata{Partition: spec.Partition, AccountID: spec.AccountID}
			current, err = s.createIdentityCenterRole(tx.Context(), a, metadata, name, path, trust, spec.Duration)
			if err != nil {
				return err
			}
			current.IdentityCenterInstanceARN, current.IdentityCenterPermissionSetARN = spec.InstanceARN, spec.PermissionSetARN
		} else {
			bound, err := authorization.BindTrustPolicy(tx.Context(), trust, s)
			if err != nil {
				return malformed(err.Error())
			}
			current.AssumeRolePolicyDocument, current.TrustPrincipalIDs = bound.Document, bound.PrincipalIDs
			current.MaxSessionDuration = int(spec.Duration / time.Second)
		}
		previous := current.IdentityPolicies
		previousBoundary := current.PermissionsBoundary
		policies := newIdentityPolicies()
		if spec.InlinePolicy != "" {
			if err := putIdentityPolicy(&policies, "Role", "AwsSSOInlinePolicy", spec.InlinePolicy); err != nil {
				return err
			}
		}
		for _, arn := range spec.ManagedPolicies {
			if !isAWSManagedPolicyARN(arn) {
				return invalid("An AWS managed policy ARN is required.")
			}
			if err := attachIdentityPolicy(a, &policies, "Role", arn); err != nil {
				return err
			}
		}
		for _, reference := range spec.CustomerManagedPolicies {
			arn, err := identityCenterPolicyARN(spec.Scope, reference)
			if err != nil {
				return err
			}
			if err := attachIdentityPolicy(a, &policies, "Role", arn); err != nil {
				return err
			}
		}
		boundaryARN := spec.BoundaryARN
		if boundaryARN != "" && !isAWSManagedPolicyARN(boundaryARN) {
			return invalid("An AWS managed boundary policy ARN is required.")
		}
		if spec.Boundary.Name != "" {
			if boundaryARN != "" {
				return invalid("Only one permissions boundary may be specified.")
			}
			boundaryARN, err = identityCenterPolicyARN(spec.Scope, spec.Boundary)
			if err != nil {
				return err
			}
		}
		b, wire := resolveBoundary(a, boundaryARN, "Role")
		if wire != nil {
			return wire
		}
		current.IdentityPolicies, current.PermissionsBoundary = policies, b
		if err := replaceIdentityCenterPolicyUsage(tx, spec.Scope, a, previous, previousBoundary, current); err != nil {
			return err
		}
		if err := tx.PutRole(spec.Scope, *current); err != nil {
			return err
		}
		result = *current
		return nil
	})
	if err != nil {
		return Role{}, err
	}
	return result, nil
}

func (s *Service) createIdentityCenterRole(ctx context.Context, a *account, m awsctx.Metadata, name, path, trust string, duration time.Duration) (*Role, error) {
	r, wire := s.createRoleResource(ctx, a, m, &iamapi.CreateRoleInput{
		RoleName: wirePointer(iamapi.RoleNameType(name)), Path: wirePointer(iamapi.PathType(path)),
		AssumeRolePolicyDocument: wirePointer(iamapi.PolicyDocumentType(trust)),
		MaxSessionDuration:       wirePointer(iamapi.RoleMaxSessionDurationType(duration / time.Second)),
	})
	if wire != nil {
		return nil, wire
	}
	return r, nil
}

func identityCenterPolicyARN(scope Scope, reference IdentityCenterPolicyReference) (string, error) {
	if err := validateName(reference.Name, "PolicyName", 128); err != nil {
		return "", err
	}
	path, err := validPath(reference.Path)
	if err != nil {
		return "", err
	}
	return "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":policy" + path + reference.Name, nil
}

// New attachments were counted by the ordinary IAM attachment helper. Reconcile
// removed attachments and boundary usage before saving only referenced customer
// policies; immutable AWS catalogue documents are never persisted as local copies.
func replaceIdentityCenterPolicyUsage(tx WriteTx, scope Scope, a *account, previous IdentityPolicies, oldBoundary *Boundary, current *Role) error {
	changed := make(map[string]struct{}, len(previous.Attached)+len(current.Attached)+2)
	for arn := range previous.Attached {
		p, err := findPolicyARN(a, arn)
		if err != nil {
			return err
		}
		p.AttachmentCount--
		changed[arn] = struct{}{}
	}
	for arn := range current.Attached {
		changed[arn] = struct{}{}
	}
	if oldBoundary != nil {
		arn := oldBoundary.PermissionsBoundaryArn
		p, err := findPolicyARN(a, arn)
		if err != nil {
			return err
		}
		p.PermissionsBoundaryUsageCount--
		changed[arn] = struct{}{}
	}
	if current.PermissionsBoundary != nil {
		arn := current.PermissionsBoundary.PermissionsBoundaryArn
		a.policies[arn].PermissionsBoundaryUsageCount++
		changed[arn] = struct{}{}
	}
	for arn := range changed {
		if !isAWSManagedPolicyARN(arn) {
			if err := tx.PutManagedPolicy(scope, *a.policies[arn]); err != nil {
				return err
			}
		}
	}
	return nil
}

func ownedIdentityCenterRole(tx ReadTx, ref IdentityCenterRoleRef) (Role, error) {
	if ref.InstanceARN == "" || ref.PermissionSetARN == "" || ref.ARN == "" || ref.ID == "" || ref.Name == "" {
		return Role{}, invalid("An exact Identity Center role incarnation is required.")
	}
	r, err := tx.Role(ref.Scope, ref.Name)
	if err != nil {
		return Role{}, err
	}
	if r.RoleId != ref.ID || r.Arn != ref.ARN || r.RoleName != ref.Name || r.IdentityCenterInstanceARN != ref.InstanceARN || r.IdentityCenterPermissionSetARN != ref.PermissionSetARN || r.ServiceLinkedService != "" {
		return Role{}, conflict("The IAM role is not the owned Identity Center incarnation.")
	}
	return r, nil
}

// IdentityCenterRole resolves exact ownership inside the ordinary role-session
// transaction. The caller must still evaluate the role's current trust policy.
func (s *Service) IdentityCenterRole(ctx context.Context, ref IdentityCenterRoleRef) (Role, error) {
	var result Role
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		result, err = ownedIdentityCenterRole(tx, ref)
		return err
	})
	return result, err
}

// RemoveIdentityCenterRole removes only the last-assignment incarnation supplied
// by Identity Center, atomically with its inline policies and attachment counts.
func (s *Service) RemoveIdentityCenterRole(ctx context.Context, ref IdentityCenterRoleRef) error {
	return s.repository.Attempt(ctx, func(tx WriteTx) error {
		current, err := ownedIdentityCenterRole(tx, ref)
		if errors.Is(err, ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		a, err := loadAccount(tx, ref.Scope)
		if err != nil {
			return err
		}
		for _, profile := range a.instanceProfiles {
			if profile.RoleId == current.RoleId {
				return conflict("Cannot delete role while it belongs to an instance profile.")
			}
		}
		if err := replaceIdentityCenterPolicyUsage(tx, ref.Scope, a, current.IdentityPolicies, current.PermissionsBoundary, &Role{}); err != nil {
			return err
		}
		return tx.DeleteRole(ref.Scope, current.RoleName)
	})
}
