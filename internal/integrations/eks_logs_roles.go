package integrations

import (
	"context"
	"slices"
	"strings"

	"stackd/internal/services/eks"
	"stackd/internal/services/iam"
)

func EKSClusterRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: "eks.amazonaws.com", RoleName: "AWSServiceRoleForAmazonEKS",
		TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonEKSServiceRolePolicy"},
		Sources:           []string{"https://docs.aws.amazon.com/eks/latest/userguide/using-service-linked-roles-eks.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSServiceRolePolicy.html"},
	}
}

type EKSClusterRoleUsage struct {
	Clusters interface {
		WithClusterRoleUsage(context.Context, string, string, func(context.Context, []eks.ClusterRoleDependency) error) error
	}
}

func (a EKSClusterRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Clusters.WithClusterRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, dependencies []eks.ClusterRoleDependency) error {
		slices.SortFunc(dependencies, func(a, b eks.ClusterRoleDependency) int {
			if n := strings.Compare(a.Region, b.Region); n != 0 {
				return n
			}
			return strings.Compare(a.ARN, b.ARN)
		})
		var usage []iam.ServiceLinkedRoleUsage
		for _, d := range dependencies {
			if len(usage) == 0 || usage[len(usage)-1].Region != d.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: d.Region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, d.ARN)
		}
		return fn(ctx, usage)
	})
}
