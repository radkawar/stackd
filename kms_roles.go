package stackd

import (
	"context"
	"maps"
	"slices"

	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
)

func kmsRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: kms.MultiRegionServicePrincipal, RoleName: kms.MultiRegionServiceRoleName,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"mrk.kms.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		UsageFailureReason: "Account owns one or more multi-Region keys",
		DefaultDescription: "Enables access to AWS services and resources required for AWS KMS Multi-Region Keys",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AWSKeyManagementServiceMultiRegionKeysServiceRolePolicy"},
		Sources:            []string{"https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-auth-slr.html", "testdata/aws/kms/multi_region.json"},
	}
}

type kmsRoleUsage struct{ service *kms.Service }

func (s kmsRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return s.service.WithMultiRegionKeys(ctx, kms.KeyOwner{Partition: ref.Scope.Partition, AccountID: ref.Scope.AccountID}, func(ctx context.Context, regions map[string][]string) error {
		var usage []iam.ServiceLinkedRoleUsage
		for _, region := range slices.Sorted(maps.Keys(regions)) {
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: regions[region]})
		}
		return fn(ctx, usage)
	})
}
