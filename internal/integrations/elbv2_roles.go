package integrations

import (
	"context"

	"stackd/internal/services/elbv2"
	"stackd/internal/services/iam"
)

type ELBV2LoadBalancerDependencies interface {
	WithLoadBalancerRoleUsage(context.Context, string, string, func(context.Context, []elbv2.LoadBalancerDependency) error) error
}

// ELBV2RoleUsage supplies real all-region load-balancer ownership to IAM's
// existing service-linked-role deletion job, including native cleanup in flight.
type ELBV2RoleUsage struct{ LoadBalancers ELBV2LoadBalancerDependencies }

func (a ELBV2RoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.LoadBalancers.WithLoadBalancerRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, dependencies []elbv2.LoadBalancerDependency) error {
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
