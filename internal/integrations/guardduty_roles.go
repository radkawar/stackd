package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/iam"
)

func GuardDutyRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: guardduty.ServicePrincipal, RoleName: guardduty.ServiceRoleName,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"guardduty.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonGuardDutyServiceRolePolicy"},
		UsageFailureReason: "GuardDuty is still enabled in one or more regions.",
		Sources:            []string{"https://docs.aws.amazon.com/guardduty/latest/ug/slr-permissions.html"},
	}
}

type GuardDutyRoleUsage struct {
	Detectors interface {
		WithRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
	}
}

func (a GuardDutyRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Detectors == nil {
		return errors.New("GuardDuty role usage owner is unavailable")
	}
	return a.Detectors.WithRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		regions := map[string][]string{}
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil {
				return errors.New("invalid retained GuardDuty resource ARN")
			}
			regions[parsed.Region] = append(regions[parsed.Region], resource)
		}
		usage := make([]iam.ServiceLinkedRoleUsage, 0, len(regions))
		for region, resources := range regions {
			slices.Sort(resources)
			usage = append(usage, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: resources})
		}
		slices.SortFunc(usage, func(a, b iam.ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
		return fn(ctx, usage)
	})
}
