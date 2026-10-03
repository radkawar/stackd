package integrations

import (
	"context"
	"stackd/internal/awsctx"
	"stackd/internal/services/ecr"
	"stackd/internal/services/iam"
)

type ECRReplicationProvisioner interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// ECRReplication uses IAM's ordinary retained service-role session authority.
type ECRReplication struct {
	Roles       ServiceRoles
	Provisioner ECRReplicationProvisioner
	sessions    serviceRoleSessions
}

func (a *ECRReplication) Ensure(ctx context.Context) error {
	return a.Provisioner.EnsureServiceLinkedRole(ctx, ecr.ReplicationServicePrincipal)
}
func (a *ECRReplication) Context(ctx context.Context, scope ecr.Scope) (context.Context, error) {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = scope.Partition, scope.AccountID, scope.Region
	ctx = awsctx.WithMetadata(ctx, m)
	role := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":role/aws-service-role/" + ecr.ReplicationServicePrincipal + "/" + ecr.ReplicationServiceRoleName
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: ecr.ReplicationServicePrincipal, Type: "AWSService"}, role, "ECRReplication", "")
}
func ECRReplicationRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{Partition: "aws", ServiceName: ecr.ReplicationServicePrincipal, RoleName: ecr.ReplicationServiceRoleName, TrustPolicy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"replication.ecr.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, DefaultDescription: "Enables access to AWS services and Resources used or managed by ECR Replication", UsageFailureReason: "The role is in use by ECR replication configurations or pending image replication.", ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/ECRReplicationServiceRolePolicy"}, Sources: []string{"https://docs.aws.amazon.com/AmazonECR/latest/userguide/slr-replication.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ECRReplicationServiceRolePolicy.html"}}
}

type ECRReplicationRoleResources interface {
	WithReplicationRoleUsage(context.Context, string, string, func(context.Context, []ecr.Scope) error) error
}
type ECRReplicationRoleUsage struct{ Registries ECRReplicationRoleResources }

func (a ECRReplicationRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Registries.WithReplicationRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, scopes []ecr.Scope) error {
		usage := make([]iam.ServiceLinkedRoleUsage, 0, len(scopes))
		for _, scope := range scopes {
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: scope.Region, ResourceARNs: []string{"arn:" + scope.Partition + ":ecr:" + scope.Region + ":" + scope.AccountID + ":registry/" + scope.AccountID}})
		}
		return fn(ctx, usage)
	})
}
