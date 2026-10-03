package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/iam"
)

// DynamoDBReplication reuses the existing service-session authority; table
// authorization and replica lifecycle stay with the DynamoDB resource owner.
type DynamoDBReplication struct {
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

func (a *DynamoDBReplication) Context(ctx context.Context, table dynamodb.TableKey) (context.Context, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = table.Partition, table.AccountID, table.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	principal := dynamodb.ReplicationServicePrincipal
	role := "arn:" + table.Partition + ":iam::" + table.AccountID + ":role/aws-service-role/" + principal + "/" + dynamodb.ReplicationServiceRoleName
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: principal, SourceARN: table.ARN(), Type: "AWSService"}, role, "DynamoDBReplication", "")
}

type DynamoDBReplicaDependencies interface {
	WithReplicaRoleUsage(context.Context, string, string, func(context.Context, []dynamodb.TableKey) error) error
}

// DynamoDBReplicaRoleUsage joins IAM's deletion decision to current membership.
type DynamoDBReplicaRoleUsage struct {
	Tables DynamoDBReplicaDependencies
}

func (a DynamoDBReplicaRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Tables.WithReplicaRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, tables []dynamodb.TableKey) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, table := range tables {
			if len(usage) == 0 || usage[len(usage)-1].Region != table.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: table.Region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, table.ARN())
		}
		return fn(ctx, usage)
	})
}
