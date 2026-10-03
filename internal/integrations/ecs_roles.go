package integrations

import (
	"context"

	"stackd/internal/services/ecs"
	"stackd/internal/services/iam"
)

// ECSClusterDependencies keeps regional cluster ownership stable during the IAM
// deletion callback. Keys are ordered by region and name.
type ECSClusterDependencies interface {
	WithClusterRoleUsage(context.Context, string, string, func(context.Context, []ecs.ClusterKey) error) error
}

// ECSRoleUsage adapts ECS-owned dependencies to IAM's linked-role deletion job.
type ECSRoleUsage struct{ Clusters ECSClusterDependencies }

func (a ECSRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Clusters.WithClusterRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, keys []ecs.ClusterKey) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, key := range keys {
			if len(usage) == 0 || usage[len(usage)-1].Region != key.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: key.Region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, key.ARN())
		}
		return fn(ctx, usage)
	})
}
