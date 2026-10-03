package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
)

// lambdaSourceSession keeps poller credentials distinct from runtime credentials.
// The shared session owner handles expiry/revocation; source services authorize
// every operation against current resource state and policies.
type lambdaSourceSession struct {
	roles    ServiceRoles
	function lambda.FunctionKey
	roleARN  string
	sessions serviceRoleSessions
}

func openLambdaSourceSession(ctx context.Context, roles ServiceRoles, function lambda.FunctionKey, roleARN string) (*lambdaSourceSession, *awswire.Error) {
	if _, wire := lambdaRoleScope(ctx, roleARN, function.ARN()); wire != nil {
		return nil, wire
	}
	session := &lambdaSourceSession{roles: roles, function: function, roleARN: roleARN}
	if _, wire := session.context(ctx); wire != nil {
		if wire.StatusCode < 500 {
			return nil, lambdaRoleDenied()
		}
		return nil, &awswire.Error{Code: "ServiceException", Message: wire.Message, StatusCode: wire.StatusCode}
	}
	return session, nil
}

func (s *lambdaSourceSession) context(ctx context.Context) (context.Context, *awswire.Error) {
	parent := awsctx.FromContext(ctx).ParentEventID
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: s.function.Partition, AccountID: s.function.Account, Region: s.function.Region, ParentEventID: parent})
	service, err := s.sessions.context(ctx, s.roles,
		awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: s.function.ARN(), Type: "AWSService"},
		s.roleARN, s.function.Name, "")
	if err != nil {
		return ctx, lambdaRoleFailure(err)
	}
	return service, nil
}
