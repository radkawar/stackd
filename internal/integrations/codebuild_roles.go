package integrations

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// CodeBuildRoles keeps PassRole, current trust and session issuance in IAM.
type CodeBuildRoles struct{ ServiceRoles }

func (a CodeBuildRoles) Validate(ctx context.Context, roleARN, projectARN string) error {
	if rejected := codeBuildRoleScope(ctx, roleARN, projectARN, true); rejected != nil {
		return rejected
	}
	if a.IAM == nil || a.Authorizer == nil {
		return codeBuildRoleDenied()
	}
	return a.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return codeBuildRoleDenied()
		}
		if rejected := a.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role.ARN, EvaluationTime: &now, Context: map[string][]string{"iam:PassedToService": {"codebuild.amazonaws.com"}, "iam:AssociatedResourceArn": {projectARN}}}); rejected != nil {
			return rejected
		}
		service := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "codebuild.amazonaws.com", SourceARN: projectARN, Type: "AWSService"})
		if rejected := a.ServiceRoles.trust(service, role, identity.RoleSessionSpec{SessionName: "AWSCodeBuild"}, now, ""); rejected != nil {
			return codeBuildRoleDenied()
		}
		return nil
	})
}

func (a CodeBuildRoles) Assume(ctx context.Context, roleARN, projectARN, buildID string) (identity.Credential, *awswire.Error) {
	if rejected := codeBuildRoleScope(ctx, roleARN, projectARN, false); rejected != nil {
		return identity.Credential{}, rejected
	}
	_, suffix, found := strings.Cut(buildID, ":")
	if !found {
		suffix = buildID
	}
	sessionName := "AWSCodeBuild-" + suffix
	if len(sessionName) > 64 || strings.Trim(sessionName, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+=,.@_-") != "" {
		return identity.Credential{}, codeBuildRoleDenied()
	}
	return a.ServiceRoles.assume(ctx, awsctx.ServicePrincipal{Name: "codebuild.amazonaws.com", SourceARN: projectARN, Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: sessionName, Duration: time.Hour}, "")
}

func (a CodeBuildRoles) Context(ctx context.Context, credential identity.Credential, region string) (context.Context, error) {
	next, rejected := serviceRoleRequestContext(ctx, credential, region, "codebuild.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	return next, nil
}

func codeBuildRoleScope(ctx context.Context, roleARN, projectARN string, allowFleet bool) *awswire.Error {
	m := awsctx.FromContext(ctx)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Service != "iam" || role.Partition != m.Partition || role.AccountID != m.AccountID || role.Region != "" || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) <= 5 {
		return codeBuildRoleDenied()
	}
	project, err := arn.Parse(projectARN)
	validResource := strings.HasPrefix(project.Resource, "project/") && len(project.Resource) > 8
	if allowFleet {
		validResource = validResource || strings.HasPrefix(project.Resource, "fleet/") && len(project.Resource) > 6
	}
	if err != nil || project.Service != "codebuild" || project.Partition != m.Partition || project.AccountID != m.AccountID || project.Region != m.Region || !validResource {
		return codeBuildRoleDenied()
	}
	return nil
}
func codeBuildRoleDenied() *awswire.Error {
	return &awswire.Error{Code: "InvalidInputException", Message: "CodeBuild is not authorized to assume the service role.", StatusCode: 400}
}
