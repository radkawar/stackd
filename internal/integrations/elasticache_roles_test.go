package integrations

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"stackd/internal/iam/managed"
	"stackd/internal/services/iam"
)

type cacheRoleUsageFixture struct {
	resources []string
	partition string
	account   string
	held      bool
	rejected  error
}

func (f *cacheRoleUsageFixture) WithElastiCacheRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	f.partition, f.account = partition, account
	if f.rejected != nil {
		return f.rejected
	}
	f.held = true
	defer func() { f.held = false }()
	return fn(ctx, f.resources)
}

func TestElastiCacheRoleTemplateUsesCapturedOfficialV4(t *testing.T) {
	template := ElastiCacheRoleTemplate()
	const policyARN = "arn:aws:iam::aws:policy/aws-service-role/ElastiCacheServiceRolePolicy"
	if template.Partition != "aws" || template.ServiceName != "elasticache.amazonaws.com" || template.RoleName != "AWSServiceRoleForElastiCache" || !slices.Equal(template.ManagedPolicyARNs, []string{policyARN}) || len(template.InlinePolicies) != 0 || template.AllowCustomSuffix {
		t.Fatalf("ElastiCache template changed official role authority: %+v", template)
	}
	if !slices.Contains(template.Sources, "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ElastiCacheServiceRolePolicy.html") || !slices.Contains(template.Sources, "internal/iam/managed/data/aws.json.gz") {
		t.Fatal("service role lost its policy provenance")
	}
	policy, ok := managed.Lookup("aws", policyARN)
	if !ok || policy.DefaultVersion != "v4" {
		t.Fatalf("official role policy is not available in the retained catalog: %+v", policy)
	}
	for _, version := range policy.Versions {
		if version.Default {
			if version.ID != "v4" || version.SHA256 != "1aa368e7f1370e96c0d34a8a516283b62867420856fb968f5bdcbbb126b2cc09" {
				t.Fatalf("captured default no longer matches sourced official policy v4: %+v", version)
			}
			return
		}
	}
	t.Fatal("retained policy has no default version")
}

func TestElastiCacheRoleUsageKeepsScopedSnapshotThroughDecision(t *testing.T) {
	owner := &cacheRoleUsageFixture{resources: []string{
		"arn:aws:elasticache:us-west-2:123456789012:cluster:failed",
		"arn:aws:elasticache:us-east-1:123456789012:replicationgroup:deleting",
		"arn:aws:elasticache:us-east-1:123456789012:cluster:creating",
	}}
	adapter := ElastiCacheRoleUsage{Clusters: owner}
	ref := iam.ServiceLinkedRoleReference{Scope: iam.Scope{Partition: "aws", AccountID: "123456789012"}}
	decision := errors.New("role remains in use")
	called := false
	err := adapter.WithServiceLinkedRoleUsage(t.Context(), ref, func(_ context.Context, usage []iam.ServiceLinkedRoleUsage) error {
		called = true
		if !owner.held || owner.partition != ref.Scope.Partition || owner.account != ref.Scope.AccountID {
			t.Fatal("IAM guard lost the scoped resource snapshot")
		}
		want := []iam.ServiceLinkedRoleUsage{
			{Region: "us-east-1", ResourceARNs: []string{"arn:aws:elasticache:us-east-1:123456789012:cluster:creating", "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:deleting"}},
			{Region: "us-west-2", ResourceARNs: []string{"arn:aws:elasticache:us-west-2:123456789012:cluster:failed"}},
		}
		if !reflect.DeepEqual(usage, want) {
			t.Fatalf("retained role usage lost resources or deterministic ordering: %+v", usage)
		}
		return decision
	})
	if !called || !errors.Is(err, decision) || owner.held {
		t.Fatal("IAM usage decision or lock release was lost", err)
	}
	owner.resources = nil
	if err := adapter.WithServiceLinkedRoleUsage(t.Context(), ref, func(_ context.Context, usage []iam.ServiceLinkedRoleUsage) error {
		if !owner.held || len(usage) != 0 {
			t.Fatal("empty usage was fabricated or escaped its snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestElastiCacheRoleUsageRejectsForeignOrMalformedResources(t *testing.T) {
	ref := iam.ServiceLinkedRoleReference{Scope: iam.Scope{Partition: "aws", AccountID: "123456789012"}}
	for _, resource := range []string{
		"arn:aws:kafka:us-east-1:123456789012:cluster/wrong/id",
		"arn:aws:elasticache:us-east-1:999999999999:cluster:wrong",
		"arn:aws-cn:elasticache:us-east-1:123456789012:cluster:wrong",
		"arn:aws:elasticache::123456789012:cluster:wrong",
		"arn:aws:elasticache:us-east-1:123456789012:cluster:",
		cacheTestARN + ":extra", cacheTestARN + "/extra",
		"arn:aws:elasticache:us-east-1:123456789012:subnetgroup:wrong",
	} {
		adapter := ElastiCacheRoleUsage{Clusters: &cacheRoleUsageFixture{resources: []string{resource}}}
		if err := adapter.WithServiceLinkedRoleUsage(t.Context(), ref, func(context.Context, []iam.ServiceLinkedRoleUsage) error {
			t.Fatalf("invalid retained owner reached IAM decision: %s", resource)
			return nil
		}); err == nil {
			t.Fatalf("invalid owner accepted: %s", resource)
		}
	}
	if err := (ElastiCacheRoleUsage{}).WithServiceLinkedRoleUsage(t.Context(), ref, func(context.Context, []iam.ServiceLinkedRoleUsage) error { return nil }); err == nil {
		t.Fatal("missing cache owner appeared unused")
	}
	failure := errors.New("cache snapshot unavailable")
	adapter := ElastiCacheRoleUsage{Clusters: &cacheRoleUsageFixture{rejected: failure}}
	if err := adapter.WithServiceLinkedRoleUsage(t.Context(), ref, func(context.Context, []iam.ServiceLinkedRoleUsage) error {
		t.Fatal("unavailable snapshot appeared unused")
		return nil
	}); !errors.Is(err, failure) {
		t.Fatal("cache repository failure was hidden", err)
	}
}
