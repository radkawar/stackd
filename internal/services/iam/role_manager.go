package iam

import "context"

func roleManagerRoleTemplate() ServiceLinkedRoleTemplate {
	return ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: roleManagerServicePrincipal, RoleName: "AWSServiceRoleForIAMRoleManager",
		TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"role-manager.iam.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSIAMRoleManagerServiceRolePolicy"},
		Sources:           []string{"testdata/aws/iam/role_manager_cleanup.json", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMRoleManagerServiceRolePolicy.html"},
	}
}

// Role Manager's account setting is IAM-owned. Keep it stable through the
// successful deletion callback using the repository's borrowed transaction.
type roleManagerRoleUsage struct{ repository Repository }

func (p roleManagerRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref ServiceLinkedRoleReference, fn func(context.Context, []ServiceLinkedRoleUsage) error) error {
	return p.repository.Update(ctx, func(tx WriteTx) error {
		settings, err := tx.AccountSettings(ref.Scope)
		if err != nil {
			return err
		}
		// TODO: Comeback verify successful Role Manager service-role deletion and exact denial diagnostics against AWS; the owned probe currently returns internal errors even after disabling the feature.
		if settings.RoleManagerEnabled {
			return &ServiceLinkedRoleInUseError{Reason: "IAM Role Manager is enabled. Disable it before deleting this service-linked role."}
		}
		return fn(tx.Context(), nil)
	})
}
