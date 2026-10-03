package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// DurableContext uses the same IAM/STS execution-role authority as the real
// runtime. Chained durable invokes do not inherit the original invoking actor.
func (a LambdaRoles) DurableContext(ctx context.Context, roleARN, functionARN, sessionName string) (context.Context, *awswire.Error) {
	if _, wire := lambdaRoleScope(ctx, roleARN, functionARN); wire != nil {
		return nil, wire
	}
	credential, wire := a.ServiceRoles.assume(ctx,
		awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: functionARN, Type: "AWSService"},
		roleARN, identity.RoleSessionSpec{SessionName: sessionName, SessionContext: map[string][]string{"lambda:sourcefunctionarn": {functionARN}}}, "")
	if wire != nil {
		return nil, wire
	}
	return serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, "lambda.amazonaws.com")
}
