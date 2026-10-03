package integrations

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/internal/services/servicecatalogappregistry"
)

const appRegistryPrincipal = "servicecatalog-appregistry.amazonaws.com"
const appRegistryRole = "AWSServiceRoleForAWSServiceCatalogAppRegistry"

// AppRegistryRoles provisions the service-linked role with the current caller's
// IAM authority and obtains sessions through the shared trust/session owner.
// Resource Groups remains responsible for current role policy authorization.
type AppRegistryRoles struct {
	Roles       ServiceRoles
	Provisioner interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
	sessions serviceRoleSessions
}

var _ servicecatalogappregistry.ApplicationRoles = (*AppRegistryRoles)(nil)

func (a *AppRegistryRoles) Context(ctx context.Context, applicationARN string, ensure bool) (context.Context, error) {
	if ensure {
		if a.Provisioner == nil {
			return nil, errors.New("AppRegistry service-linked-role provisioning is not configured")
		}
		if err := a.Provisioner.EnsureServiceLinkedRole(ctx, appRegistryPrincipal); err != nil {
			return nil, err
		}
	}
	metadata := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		metadata.ParentEventID = parent
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	roleARN := "arn:" + metadata.Partition + ":iam::" + metadata.AccountID + ":role/aws-service-role/" + appRegistryPrincipal + "/" + appRegistryRole
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: appRegistryPrincipal, SourceARN: applicationARN, Type: "AWSService"}, roleARN, "AppRegistry", "")
}

// AppRegistryRoleTemplate uses the captured AWS managed policy, whose default v4
// scopes Resource Groups mutation to EnableAWSServiceCatalogAppRegistry=true.
func AppRegistryRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: appRegistryPrincipal, RoleName: appRegistryRole,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"servicecatalog-appregistry.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AWSServiceCatalogAppRegistryServiceRolePolicy"},
		UsageFailureReason: "The role is in use by AppRegistry applications.",
		Sources: []string{
			"https://docs.aws.amazon.com/servicecatalog/latest/arguide/slr-appregistry.html",
			"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSServiceCatalogAppRegistryServiceRolePolicy.html",
		},
	}
}

// AppRegistryRoleUsage supplies IAM with the current applications across every
// region, keeping their shared transaction open through the deletion decision.
type AppRegistryRoleUsage struct {
	Applications interface {
		WithApplicationRoleUsage(context.Context, string, string, func(context.Context, []servicecatalogappregistry.ApplicationRoleDependency) error) error
	}
}

var _ iam.ServiceLinkedRoleUsageProvider = AppRegistryRoleUsage{}

func (a AppRegistryRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Applications.WithApplicationRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, dependencies []servicecatalogappregistry.ApplicationRoleDependency) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, dependency := range dependencies {
			if len(usage) == 0 || usage[len(usage)-1].Region != dependency.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: dependency.Region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, dependency.ARN)
		}
		return fn(ctx, usage)
	})
}
