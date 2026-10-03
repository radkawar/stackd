package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/resourcegroups"
)

const resourceGroupsLifecyclePrincipal = "resourcegroups.amazonaws.com"
const resourceGroupsTagSyncPrincipal = "resource-groups.amazonaws.com"

type ResourceGroupsRoles struct {
	Roles ServiceRoles
	IAM   interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
	Repository resourcegroups.Repository
}

var _ resourcegroups.Roles = ResourceGroupsRoles{}

// ResourceGroupsRoleTemplate reuses the captured managed-policy catalog v1.
func ResourceGroupsRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: resourceGroupsLifecyclePrincipal, RoleName: "AWSServiceRoleForResourceGroups",
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"resourcegroups.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/ResourceGroupsServiceRolePolicy"},
		UsageFailureReason: "Group Lifecycle Events remains enabled.",
		Sources:            []string{"https://docs.aws.amazon.com/ARG/latest/userguide/using-service-linked-roles.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ResourceGroupsServiceRolePolicy.html"},
	}
}

func (a ResourceGroupsRoles) EnsureLifecycleRole(ctx context.Context) error {
	if a.IAM == nil {
		return errors.New("resource groups service-linked IAM role authority is not configured")
	}
	return a.IAM.EnsureServiceLinkedRole(ctx, resourceGroupsLifecyclePrincipal)
}
func (a ResourceGroupsRoles) AssumeLifecycleRole(ctx context.Context, scope resourcegroups.Scope) (context.Context, error) {
	roleARN := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":role/aws-service-role/" + resourceGroupsLifecyclePrincipal + "/AWSServiceRoleForResourceGroups"
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: resourceGroupsLifecyclePrincipal, Type: "Service"}, roleARN, identity.RoleSessionSpec{SessionName: "ResourceGroupsLifecycle"}, "")
	if rejected != nil {
		return nil, rejected
	}
	result, rejected := serviceRoleRequestContext(ctx, credential, scope.Region, resourceGroupsLifecyclePrincipal)
	if rejected != nil {
		return nil, rejected
	}
	return result, nil
}
func (a ResourceGroupsRoles) AssumeTagSyncRole(ctx context.Context, roleARN, groupARN string) (context.Context, error) {
	parts := strings.SplitN(groupARN, ":", 6)
	if len(parts) != 6 {
		return nil, errors.New("invalid application group ARN")
	}
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: resourceGroupsTagSyncPrincipal, SourceARN: groupARN, Type: "Service"}, roleARN, identity.RoleSessionSpec{SessionName: "ResourceGroupsTagSync"}, "")
	if rejected != nil {
		return nil, rejected
	}
	result, rejected := serviceRoleRequestContext(ctx, credential, parts[3], resourceGroupsTagSyncPrincipal)
	if rejected != nil {
		return nil, rejected
	}
	return result, nil
}

// The account setting holds usage even when there are currently no groups.
// IAM's decision shares the owner transaction; disabling permits deletion.
func (a ResourceGroupsRoles) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Repository == nil {
		return errors.New("resource groups lifecycle repository is not configured")
	}
	return a.Repository.Update(ctx, func(r resourcegroups.Transaction) error {
		rows, err := r.LifecycleAccounts()
		if err != nil {
			return err
		}
		var usage []iam.ServiceLinkedRoleUsage
		for _, account := range rows {
			if ref.ServiceName != resourceGroupsLifecyclePrincipal || account.Partition != ref.Scope.Partition || account.AccountID != ref.Scope.AccountID || account.Desired != "ACTIVE" {
				continue
			}
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: account.Region})
		}
		return fn(r.Context(), usage)
	})
}
