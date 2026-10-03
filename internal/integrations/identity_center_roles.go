package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/identitycenter"
)

// IdentityCenterRoles delegates reserved-role lifecycle to IAM and credential
// issuance to its existing transactional service-role authority. It never copies
// permission-set documents into credentials or impersonates an account root.
type IdentityCenterRoles struct {
	IAM      *iam.Service
	Sessions ServiceRoles
}

var _ identitycenter.Roles = IdentityCenterRoles{}

func (a IdentityCenterRoles) Provision(ctx context.Context, spec identitycenter.RoleSpec) (identitycenter.Provisioning, error) {
	if a.IAM == nil {
		return identitycenter.Provisioning{}, errors.New("Identity Center IAM authority is not configured")
	}
	if spec.PermissionSet.InstanceARN != spec.Instance.ARN {
		return identitycenter.Provisioning{}, errors.New("permission set does not belong to the Identity Center instance")
	}
	in := iam.IdentityCenterRoleSpec{
		Scope: iam.Scope{Partition: spec.Instance.Partition, AccountID: spec.AccountID}, Region: spec.Instance.Region,
		InstanceARN: spec.Instance.ARN, PermissionSetARN: spec.PermissionSet.ARN, Name: spec.PermissionSet.Name,
		InlinePolicy: spec.PermissionSet.InlinePolicy, ManagedPolicies: spec.PermissionSet.ManagedPolicies,
		BoundaryARN: spec.PermissionSet.BoundaryARN, Boundary: iam.IdentityCenterPolicyReference{Name: spec.PermissionSet.Boundary.Name, Path: spec.PermissionSet.Boundary.Path},
		Duration:                spec.PermissionSet.Duration,
		CustomerManagedPolicies: make([]iam.IdentityCenterPolicyReference, len(spec.PermissionSet.CustomerManagedPolicies)),
	}
	for i, reference := range spec.PermissionSet.CustomerManagedPolicies {
		in.CustomerManagedPolicies[i] = iam.IdentityCenterPolicyReference{Name: reference.Name, Path: reference.Path}
	}
	role, err := a.IAM.ProvisionIdentityCenterRole(ctx, in)
	if err != nil {
		return identitycenter.Provisioning{}, err
	}
	return identitycenter.Provisioning{InstanceARN: spec.Instance.ARN, PermissionSetARN: spec.PermissionSet.ARN, AccountID: spec.AccountID, RoleARN: role.Arn, RoleID: role.RoleId, RoleName: role.RoleName}, nil
}

func identityCenterRoleReference(provisioning identitycenter.Provisioning) (iam.IdentityCenterRoleRef, error) {
	parts := strings.SplitN(provisioning.RoleARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "iam" || parts[3] != "" || parts[4] != provisioning.AccountID || !strings.HasPrefix(parts[5], "role/aws-reserved/sso.amazonaws.com/") || !strings.HasPrefix(provisioning.InstanceARN, "arn:"+parts[1]+":sso:::instance/") {
		return iam.IdentityCenterRoleRef{}, errors.New("invalid Identity Center role ownership reference")
	}
	return iam.IdentityCenterRoleRef{Scope: iam.Scope{Partition: parts[1], AccountID: provisioning.AccountID}, InstanceARN: provisioning.InstanceARN, PermissionSetARN: provisioning.PermissionSetARN, ARN: provisioning.RoleARN, ID: provisioning.RoleID, Name: provisioning.RoleName}, nil
}

func (a IdentityCenterRoles) Remove(ctx context.Context, provisioning identitycenter.Provisioning) error {
	if a.IAM == nil {
		return errors.New("Identity Center IAM authority is not configured")
	}
	ref, err := identityCenterRoleReference(provisioning)
	if err != nil {
		return err
	}
	return a.IAM.RemoveIdentityCenterRole(ctx, ref)
}

func (a IdentityCenterRoles) Credentials(ctx context.Context, instance identitycenter.Instance, permissionSet identitycenter.PermissionSet, provisioning identitycenter.Provisioning, username string) (identity.Credential, error) {
	if a.IAM == nil {
		return identity.Credential{}, errors.New("Identity Center IAM authority is not configured")
	}
	ref, err := identityCenterRoleReference(provisioning)
	if err != nil {
		return identity.Credential{}, err
	}
	if instance.ARN != ref.InstanceARN || instance.Partition != ref.Partition || permissionSet.InstanceARN != instance.ARN || permissionSet.ARN != ref.PermissionSetARN {
		return identity.Credential{}, errors.New("provisioning does not belong to the Identity Center instance and permission set")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = instance.Partition, instance.AccountID, instance.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	credential, rejected := a.Sessions.assumeResolvedSession(ctx,
		awsctx.ServicePrincipal{Name: "sso.amazonaws.com", SourceARN: instance.ARN, Type: "AWSService"}, "",
		func(ctx context.Context) (string, identity.RoleSessionSpec, error) {
			role, err := a.IAM.IdentityCenterRole(ctx, ref)
			if err != nil {
				return "", identity.RoleSessionSpec{}, err
			}
			return role.Arn, identity.RoleSessionSpec{Role: identity.Principal{ID: role.RoleId}, SessionName: username, Duration: time.Duration(role.MaxSessionDuration) * time.Second}, nil
		})
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	return credential, nil
}
