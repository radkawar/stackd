package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/iam"
)

const elastiCacheServicePrincipal = "elasticache.amazonaws.com"
const elastiCacheServiceRole = "AWSServiceRoleForElastiCache"

// ElastiCacheRoleTemplate uses the captured AWS-managed v4 policy without
// adding permissions that the official ElastiCache service role does not have.
func ElastiCacheRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: elastiCacheServicePrincipal, RoleName: elastiCacheServiceRole,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"elasticache.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/ElastiCacheServiceRolePolicy"},
		UsageFailureReason: "The role is in use by ElastiCache clusters or replication groups.",
		Sources: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/using-service-linked-roles.html",
			"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ElastiCacheServiceRolePolicy.html",
			"internal/iam/managed/data/aws.json.gz",
		},
	}
}

// ElastiCacheRoleUsage holds the cache resource snapshot through IAM's decision,
// including retained placement intents and interfaces during failed teardown.
type ElastiCacheRoleUsage struct {
	Clusters interface {
		WithElastiCacheRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
	}
}

func (a ElastiCacheRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Clusters == nil {
		return errors.New("native ElastiCache role usage owner is unavailable")
	}
	return a.Clusters.WithElastiCacheRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		byRegion := make(map[string][]string)
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil || !validElastiCacheOwner(parsed) || parsed.Partition != ref.Scope.Partition || parsed.AccountID != ref.Scope.AccountID {
				return errors.New("invalid retained ElastiCache cluster scope")
			}
			byRegion[parsed.Region] = append(byRegion[parsed.Region], resource)
		}
		usage := make([]iam.ServiceLinkedRoleUsage, 0, len(byRegion))
		for region, resources := range byRegion {
			slices.Sort(resources)
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: resources})
		}
		slices.SortFunc(usage, func(a, b iam.ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
		return fn(ctx, usage)
	})
}
