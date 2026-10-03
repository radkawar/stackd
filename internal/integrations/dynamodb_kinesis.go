package integrations

import (
	"context"
	"sort"

	"stackd/internal/awsctx"
	"stackd/internal/services/dynamodb"
	"stackd/internal/services/iam"
)

// DynamoDBKinesis assumes the protected service-linked role for target calls.
// Its cached session retains identity only; target IAM is evaluated on every call.
type DynamoDBKinesis struct {
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

func (a *DynamoDBKinesis) Context(ctx context.Context, table dynamodb.TableKey) (context.Context, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition = table.Partition
	metadata.AccountID = table.AccountID
	metadata.Region = table.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	principal := dynamodb.KinesisServicePrincipal
	role := "arn:" + table.Partition + ":iam::" + table.AccountID + ":role/aws-service-role/" + principal + "/" + dynamodb.KinesisServiceRoleName
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: principal, SourceARN: table.ARN(), Type: "AWSService"}, role, "DynamoDBKinesisReplication", "")
}

type DynamoDBKinesisDependencies interface {
	WithKinesisRoleUsage(context.Context, string, string, func(context.Context, []dynamodb.TableKey) error) error
}
type DynamoDBKinesisRoleUsage struct{ Tables DynamoDBKinesisDependencies }

func (a DynamoDBKinesisRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Tables.WithKinesisRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, tables []dynamodb.TableKey) error {
		sort.Slice(tables, func(i, j int) bool {
			if tables[i].Region != tables[j].Region {
				return tables[i].Region < tables[j].Region
			}
			return tables[i].Name < tables[j].Name
		})
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
