package stackd

import (
	"context"

	"stackd/internal/services/iam"
	"stackd/internal/services/organizations"
)

func organizationRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: organizations.ServicePrincipal, RoleName: organizations.ServiceLinkedRoleName,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		DefaultDescription: "Service-linked role used by AWS Organizations to enable integration of other AWS services with Organizations.",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AWSOrganizationsServiceTrustPolicy"},
		Sources:            []string{"https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html#orgs_integrate_services-using_slrs", "testdata/aws/iam/organizations_roles.json"},
	}
}

// organizationRoleUsage holds membership stable through the IAM deletion
// callback. Both typed repositories join the IAM transaction's context.
type organizationRoleUsage struct {
	organization *organizations.Service
	repository   iam.Repository
}

func (s organizationRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return s.repository.Update(ctx, func(tx iam.WriteTx) error {
		ctx := tx.Context()
		arn, err := s.organization.ServiceRoleDependency(ctx, ref.Scope.Partition, ref.Scope.AccountID)
		if err != nil {
			return err
		}
		var usage []iam.ServiceLinkedRoleUsage
		if arn != "" {
			// TODO: Comeback capture exact Organizations service-role deletion diagnostics and fresh organization/billing-mode provisioning, including reuse of an existing role, against owned AWS accounts.
			usage = []iam.ServiceLinkedRoleUsage{{Region: "us-east-1", ResourceARNs: []string{arn}}}
		}
		return fn(ctx, usage)
	})
}
