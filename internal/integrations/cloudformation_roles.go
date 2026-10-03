package integrations

import (
	"context"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// CloudFormationRoles uses the existing IAM trust evaluator and STS credential
// issuer; deployment jobs obtain current authority for every resource command.
type CloudFormationRoles struct{ Roles ServiceRoles }

func cloudFormationPrincipal(stackID string) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "cloudformation.amazonaws.com", SourceARN: stackID, Type: "AWSService"}
}
func (a CloudFormationRoles) Validate(ctx context.Context, stackID, roleARN string) error {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return &awswire.Error{Code: "ValidationError", Message: "CloudFormation role authority is not configured.", StatusCode: 400}
	}
	return a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, e := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if e != nil {
			return &awswire.Error{Code: "ValidationError", Message: "Role is invalid or cannot be assumed: " + roleARN, StatusCode: 400}
		}
		if denied := a.Roles.trust(awsctx.WithServicePrincipal(ctx, cloudFormationPrincipal(stackID)), role, identity.RoleSessionSpec{SessionName: "AWSCloudFormation"}, now, ""); denied != nil {
			return denied
		}
		return nil
	})
}
func (a CloudFormationRoles) Context(ctx context.Context, stackID, roleARN string) (context.Context, error) {
	credential, rejected := a.Roles.assume(ctx, cloudFormationPrincipal(stackID), roleARN, identity.RoleSessionSpec{SessionName: "AWSCloudFormation"}, "")
	if rejected != nil {
		return nil, rejected
	}
	out, rejected := serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, "cloudformation.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}
