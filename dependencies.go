package stackd

import (
	"context"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
	"stackd/internal/services/s3"
	"stackd/internal/services/sts"
)

// InventoryORCEncoder is the native S3 report-format boundary. It is optional
// for CSV/Parquet inventory; ORC reports require a configured Apache ORC engine.
type InventoryORCEncoder = s3.InventoryORCEncoder

type organizationControls struct{ service *organizations.Service }

func (o organizationControls) PrincipalOrganization(ctx context.Context) (string, string, error) {
	return o.service.PrincipalOrganization(ctx)
}

func (o organizationControls) ServiceControlPolicies(ctx context.Context) ([]policy.PolicyLevel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return o.service.ServiceControlPolicies(ctx, awsctx.FromContext(ctx).AccountID)
}

func (o organizationControls) ResourceControlPolicies(ctx context.Context, accountID string) (authorization.ResourceControlSet, error) {
	return o.service.ResourceControlPolicies(ctx, accountID)
}

type iamRoles struct{ service *iam.Service }

func (i iamRoles) RoleForAssumption(ctx context.Context, arn string) (sts.RoleSnapshot, error) {
	r, err := i.service.RoleForAssumption(ctx, arn)
	if err != nil {
		return sts.RoleSnapshot{}, err
	}
	return sts.RoleSnapshot{ARN: r.ARN, ID: r.ID, Name: r.Name, TrustPolicy: r.TrustPolicy, TrustPrincipalIDs: r.TrustPrincipalIDs, MaxSessionDuration: r.MaxSessionDuration, Tags: r.Tags, ServiceLinkedRole: r.ServiceLinkedRole}, nil
}

func (i iamRoles) ResolveManagedPolicyDocuments(ctx context.Context, arns []string) ([]string, error) {
	return i.service.ResolveManagedPolicyDocuments(ctx, arns)
}
