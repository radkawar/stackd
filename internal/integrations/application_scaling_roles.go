package integrations

import (
	"context"

	aas "stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/iam"
)

type ApplicationScalingDependencies interface {
	WithRoleUsage(context.Context, string, string, func(context.Context, []aas.TargetKey) error) error
}

// ApplicationScalingRoleUsage holds scoped targets stable while IAM decides
// deletion of an Application Auto Scaling service-linked role.
type ApplicationScalingRoleUsage struct {
	Targets ApplicationScalingDependencies
}

func (a ApplicationScalingRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Targets.WithRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, keys []aas.TargetKey) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, key := range keys {
			principal, _ := aas.LinkedRole(key)
			if principal != ref.ServiceName {
				continue
			}
			if len(usage) == 0 || usage[len(usage)-1].Region != key.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: key.Region})
			}
			last := &usage[len(usage)-1]
			resource := aas.ResourceARN(key)
			if len(last.ResourceARNs) == 0 || last.ResourceARNs[len(last.ResourceARNs)-1] != resource {
				last.ResourceARNs = append(last.ResourceARNs, resource)
			}
		}
		return fn(ctx, usage)
	})
}
