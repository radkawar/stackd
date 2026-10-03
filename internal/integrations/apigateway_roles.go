package integrations

import (
	"context"
	"strconv"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// GatewayInvocationRoles uses current IAM trust and ordinary STS session issuance.
// Authorizer result caching belongs to Gateway; this adapter does not cache authority.
type GatewayInvocationRoles struct {
	Roles ServiceRoles
	Clock clock.Clock
}

func (a GatewayInvocationRoles) InvocationContext(ctx context.Context, roleARN string, rest bool) (context.Context, *awswire.Error) {
	session := identity.RoleSessionSpec{SessionName: "BackplaneAssumeRoleSession", Duration: time.Hour}
	if !rest {
		session.SessionName = strconv.FormatInt(a.Clock.Now().UnixNano(), 10)
		session.Duration = 15 * time.Minute
	}
	// Fresh native trust policies require BOTH source keys to be absent.
	// The execute-api invocation ARN belongs to resource-policy invocation,
	// not this service's AssumeRole request.
	source := awsctx.ServicePrincipal{Name: "apigateway.amazonaws.com", Type: "AssumedRole"}
	credential, rejected := a.Roles.assume(ctx, source, roleARN, session, "")
	if rejected != nil {
		return nil, rejected
	}
	return serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, source.Name)
}
