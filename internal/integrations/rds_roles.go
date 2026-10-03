package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

const rdsServicePrincipal = "rds.amazonaws.com"
const rdsServiceRole = "AWSServiceRoleForRDS"

// RDSRoles uses the existing protected role and session owner for retained
// database work. Recovery never forges the creator's identity or saves credentials.
type RDSRoles struct {
	Roles       ServiceRoles
	Provisioner interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
	sessions serviceRoleSessions
}

func (a *RDSRoles) context(ctx context.Context, resource string, ensure bool) (context.Context, error) {
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
		ctx = awsctx.WithMetadata(ctx, m)
	}
	parsed, err := arn.Parse(resource)
	if err != nil || parsed.Service != "rds" || parsed.Partition != m.Partition || parsed.AccountID != m.AccountID || parsed.Region != m.Region {
		return nil, errors.New("invalid RDS service resource scope")
	}
	if ensure {
		if err := a.Provisioner.EnsureServiceLinkedRole(ctx, rdsServicePrincipal); err != nil {
			return nil, err
		}
	}
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/" + rdsServicePrincipal + "/" + rdsServiceRole
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: rdsServicePrincipal, SourceARN: resource, Type: "AWSService"}, role, "RDS", "")
}

func RDSRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: rdsServicePrincipal, RoleName: rdsServiceRole,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["rds.amazonaws.com"]}}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonRDSServiceRolePolicy"},
		UsageFailureReason: "The role is in use by RDS databases or snapshots.",
		Sources:            []string{"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAM.ServiceLinkedRoles.html", "testdata/service_linked_roles_aws.json"},
	}
}

type RDSRoleResources interface {
	WithRDSRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
}
type RDSRoleUsage struct{ Databases, Documents RDSRoleResources }

func (a RDSRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	publish := func(ctx context.Context, resources []string) error {
		byRegion := map[string][]string{}
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil {
				return errors.New("invalid retained RDS resource ARN")
			}
			byRegion[parsed.Region] = append(byRegion[parsed.Region], resource)
		}
		usage := make([]iam.ServiceLinkedRoleUsage, 0, len(byRegion))
		for region, resources := range byRegion {
			slices.Sort(resources)
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: resources})
		}
		slices.SortFunc(usage, func(a, b iam.ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
		return fn(ctx, usage)
	}
	return a.Databases.WithRDSRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		if a.Documents == nil {
			return publish(ctx, resources)
		}
		return a.Documents.WithRDSRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, documents []string) error {
			return publish(ctx, append(resources, documents...))
		})
	})
}
