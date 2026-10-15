package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/iam"
)

// KafkaRoleUsage keeps the service-linked role in use until native brokers and
// their EC2 network attachments have completed teardown.
type KafkaRoleUsage struct {
	Clusters interface {
		WithKafkaRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
	}
}

func (a KafkaRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Clusters == nil {
		return errors.New("native Kafka role usage owner is unavailable")
	}
	return a.Clusters.WithKafkaRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		byRegion := make(map[string][]string)
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil || parsed.Service != "kafka" || parsed.Partition != ref.Scope.Partition || parsed.AccountID != ref.Scope.AccountID || parsed.Region == "" || !strings.HasPrefix(parsed.Resource, "cluster/") {
				return errors.New("invalid retained Kafka cluster scope")
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
