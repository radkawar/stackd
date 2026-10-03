package iam

import (
	"context"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func authorizeInstanceProfileDependencies(ctx context.Context, authorizer authorization.Authorizer, a *account, m awsctx.Metadata) *awswire.Error {
	in, ok := awsapi.Input[iamapi.AddRoleToInstanceProfileInput](ctx)
	if !ok {
		return nil
	}
	r, err := findRole(a, inputString(in.RoleName))
	if err != nil {
		return err
	}
	service := "ec2.amazonaws.com"
	if m.Partition == "aws-cn" {
		service += ".cn"
	}
	return authorizer.Authorize(ctx, authorization.Request{
		Action: "iam:PassRole", ResourceARN: r.Arn, EvaluationTime: &a.currentTime,
		Context: map[string][]string{
			"iam:PassedToService": {service},
			// IAM has no concrete EC2 instance yet during this operation.
			"iam:AssociatedResourceArn": {"arn:" + m.Partition + ":ec2:*:" + m.AccountID + ":instance/*"},
		},
	})
}
