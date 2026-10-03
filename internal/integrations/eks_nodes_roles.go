package integrations

import (
	"context"
	"stackd/internal/services/iam"
	"strings"
)

func NodegroupRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: eksNodePrincipal, RoleName: eksNodeRoleName,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks-nodegroup.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		DefaultDescription: "Allows Amazon EKS to create and manage resources for managed node groups.",
		UsageFailureReason: "Managed EKS nodegroups still use this role.",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AWSServiceRoleForAmazonEKSNodegroup"},
		Sources:            []string{"https://docs.aws.amazon.com/eks/latest/userguide/using-service-linked-roles-eks-nodegroups.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSServiceRoleForAmazonEKSNodegroup.html"},
	}
}

type EKSNodegroupRoleResources interface {
	WithNodegroupRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
}
type NodegroupRoleUsage struct{ Groups EKSNodegroupRoleResources }

func (a NodegroupRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Groups.WithNodegroupRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		usage := []iam.ServiceLinkedRoleUsage{}
		for _, resource := range resources {
			region := strings.SplitN(resource, ":", 5)[3]
			if len(usage) == 0 || usage[len(usage)-1].Region != region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region})
			}
			usage[len(usage)-1].ResourceARNs = append(usage[len(usage)-1].ResourceARNs, resource)
		}
		return fn(ctx, usage)
	})
}
