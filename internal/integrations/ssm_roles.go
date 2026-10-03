package integrations

import (
	"context"
	"errors"

	"stackd/internal/services/iam"
)

// SSMRoleTemplate uses the native role trust and the already captured v17
// AmazonSSMServiceRolePolicy, including cloudwatch:DescribeAlarms. Other SSM
// consumers must join its usage boundary when their execution is implemented.
func SSMRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: "ssm.amazonaws.com", RoleName: "AWSServiceRoleForAmazonSSM",
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ssm.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		DefaultDescription: "Provides access to AWS Resources managed or used by Amazon SSM.",
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonSSMServiceRolePolicy"},
		UsageFailureReason: "Run Command alarm monitoring remains active.",
		Sources: []string{
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/using-service-linked-roles-service-action-1.html",
			"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonSSMServiceRolePolicy.html",
		},
	}
}

// SSMRoleUsage keeps monitored-command admission atomic with IAM deletion.
type SSMRoleUsage struct {
	Commands interface {
		WithAlarmRoleUsage(context.Context, string, string, func(context.Context, []string) error) error
	}
}

func (a SSMRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	if a.Commands == nil {
		return errors.New("SSM alarm role usage owner is unavailable")
	}
	return a.Commands.WithAlarmRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, regions []string) error {
		usage := make([]iam.ServiceLinkedRoleUsage, len(regions))
		for i, region := range regions {
			usage[i] = iam.ServiceLinkedRoleUsage{Region: region}
		}
		return fn(ctx, usage)
	})
}
