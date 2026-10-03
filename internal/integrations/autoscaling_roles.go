package integrations

import (
	"context"
	"strings"

	"stackd/internal/services/iam"
)

// AutoScalingGroupDependencies keeps actual group ownership stable while IAM
// makes its service-linked-role deletion decision, including retiring groups.
type AutoScalingGroupDependencies interface {
	WithRoleUsage(context.Context, string, string, string, func(context.Context, []string) error) error
}

type AutoScalingRoleUsage struct{ Groups AutoScalingGroupDependencies }

func (a AutoScalingRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Groups.WithRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, ref.ARN, func(ctx context.Context, resources []string) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, resource := range resources {
			region := strings.SplitN(resource, ":", 5)[3]
			if len(usage) == 0 || usage[len(usage)-1].Region != region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, resource)
		}
		return fn(ctx, usage)
	})
}
