package integrations

import (
	"context"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// CodePipelineRoles makes IAM authoritative for PassRole and service trust.
type CodePipelineRoles struct{ ServiceRoles }

func (a CodePipelineRoles) Validate(ctx context.Context, roleARN, pipelineARN string) error {
	if a.IAM == nil || a.Authorizer == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "CodePipeline role authority is unavailable", StatusCode: 500}
	}
	return a.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return pipelineRoleDenied(roleARN)
		}
		if rejected := a.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role.ARN, EvaluationTime: &now, Context: map[string][]string{"iam:PassedToService": {"codepipeline.amazonaws.com"}, "iam:AssociatedResourceArn": {pipelineARN}}}); rejected != nil {
			return rejected
		}
		service := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "codepipeline.amazonaws.com", SourceARN: pipelineARN, Type: "AWSService"})
		if rejected := a.ServiceRoles.trust(service, role, identity.RoleSessionSpec{SessionName: "AWSCodePipeline"}, now, ""); rejected != nil {
			if rejected.StatusCode >= 500 {
				return rejected
			}
			return pipelineRoleDenied(roleARN)
		}
		return nil
	})
}

func pipelineRoleDenied(roleARN string) *awswire.Error {
	return &awswire.Error{Code: "InvalidStructureException", Message: "CodePipeline is not authorized to perform AssumeRole on role " + roleARN, StatusCode: 400}
}
