package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/services/iam"
)

func MQRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: "mq.amazonaws.com", RoleName: "AWSServiceRoleForAmazonMQ",
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["mq.amazonaws.com"]}}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonMQServiceRolePolicy"},
		UsageFailureReason: "The role is in use by Amazon MQ RabbitMQ brokers.",
		Sources:            []string{"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-service-linked-roles.html"},
	}
}

type MQRoleUsage struct {
	Brokers interface {
		WithMQRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
	}
}

func (a MQRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Brokers == nil {
		return errors.New("MQ role usage owner is unavailable")
	}
	return a.Brokers.WithMQRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		byRegion := map[string][]string{}
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil {
				return errors.New("invalid retained MQ resource ARN")
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
