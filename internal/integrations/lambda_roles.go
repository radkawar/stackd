package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	runtime "stackd/compute/lambda"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

// LambdaRoles separates deployment's PassRole from Lambda's service assumption.
// Its methods own their IAM transaction and must not run inside WithSession.
type LambdaRoles struct {
	ServiceRoles
}

func (a LambdaRoles) Validate(ctx context.Context, roleARN, functionARN string) *awswire.Error {
	function, apiErr := lambdaRoleScope(ctx, roleARN, functionARN)
	if apiErr != nil {
		return apiErr
	}
	if a.IAM == nil || a.Authorizer == nil {
		return lambdaRoleFailure(errors.New("lambda role authority is not configured"))
	}
	return lambdaRoleFailure(a.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return lambdaRoleDenied()
		}
		if apiErr := a.Authorizer.Authorize(ctx, authorization.Request{
			Action: "iam:PassRole", ResourceARN: role.ARN, EvaluationTime: &now,
			Context: map[string][]string{
				"iam:PassedToService":       {"lambda.amazonaws.com"},
				"iam:AssociatedResourceArn": {functionARN},
			},
		}); apiErr != nil {
			return apiErr
		}
		if apiErr := a.trust(ctx, role, functionARN, strings.TrimPrefix(function.Resource, "function:"), now); apiErr != nil {
			return apiErr
		}
		return nil
	}))
}

func (a LambdaRoles) Assume(ctx context.Context, roleARN, functionARN, sessionName string) (runtime.Credentials, *awswire.Error) {
	if _, wire := lambdaRoleScope(ctx, roleARN, functionARN); wire != nil {
		return runtime.Credentials{}, wire
	}
	// Service execution sessions use the function name, which can be one character.
	if len(sessionName) == 0 || len(sessionName) > 64 || strings.Trim(sessionName, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+=,.@_-") != "" {
		return runtime.Credentials{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "Invalid execution-role session name.", StatusCode: 400}
	}
	credential, wire := a.ServiceRoles.assume(ctx,
		awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: functionARN, Type: "AWSService"},
		roleARN, identity.RoleSessionSpec{SessionName: sessionName, SessionContext: map[string][]string{"lambda:sourcefunctionarn": {functionARN}}}, "")
	if wire != nil {
		if wire.StatusCode >= 500 {
			return runtime.Credentials{}, &awswire.Error{Code: "ServiceException", Message: wire.Message, StatusCode: 500}
		}
		return runtime.Credentials{}, lambdaRoleDenied()
	}
	return runtime.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, Expiration: credential.Expiration}, nil
}

func (a LambdaRoles) trust(ctx context.Context, role iam.RoleSnapshot, functionARN, sessionName string, now time.Time) *awswire.Error {
	if wire := a.ServiceRoles.trust(lambdaServiceContext(ctx, functionARN), role, identity.RoleSessionSpec{SessionName: sessionName}, now, ""); wire != nil {
		return lambdaRoleDenied()
	}
	return nil
}

func lambdaServiceContext(ctx context.Context, functionARN string) context.Context {
	return awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: functionARN, Type: "AWSService"})
}

func lambdaRoleScope(ctx context.Context, roleARN, functionARN string) (arn.ARN, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	role, roleErr := arn.Parse(roleARN)
	function, functionErr := arn.Parse(functionARN)
	if roleErr != nil || role.Partition != m.Partition || role.Service != "iam" || role.Region != "" || role.AccountID != m.AccountID || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) <= len("role/") {
		return arn.ARN{}, lambdaRoleDenied()
	}
	if functionErr != nil || function.Partition != m.Partition || function.Service != "lambda" || function.AccountID != m.AccountID || function.Region == "" || function.Region != m.Region || !strings.HasPrefix(function.Resource, "function:") || len(function.Resource) <= len("function:") || strings.Contains(strings.TrimPrefix(function.Resource, "function:"), ":") {
		return arn.ARN{}, &awswire.Error{Code: "InvalidParameterValueException", Message: "Execution-role assumption requires an unqualified function ARN in the request account, partition and region.", StatusCode: 400}
	}
	return function, nil
}

func lambdaRoleDenied() *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterValueException", Message: "The role defined for the function cannot be assumed by Lambda.", StatusCode: 400}
}

func lambdaRoleFailure(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return &awswire.Error{Code: "ServiceException", Message: "Execution-role authority transaction failed.", StatusCode: 500}
}
