package apigatewayexec

import (
	"context"
	"net/http"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// CallerCredentialsARN selects the authenticated REST API caller rather than an
// API Gateway service principal or an assumed integration role.
const CallerCredentialsARN = "arn:aws:iam::*:user/*"

// IntegrationContext selects integration authority without changing the owned
// invocation's request identity or causal parent. The input context already
// contains the resource-policy service principal used when credentials are absent.
func IntegrationContext(ctx context.Context, credentialsARN string, roles InvocationRoles, caller awsctx.Metadata, rest bool) (context.Context, *awswire.Error) {
	switch credentialsARN {
	case "":
		return ctx, nil
	case CallerCredentialsARN:
		invocation := awsctx.FromContext(ctx)
		caller.Region = invocation.Region
		caller.RequestID = invocation.RequestID
		caller.ParentEventID = invocation.ParentEventID
		caller.TraceHeader = invocation.TraceHeader
		caller.InvokedBy = "apigateway.amazonaws.com"
		return awsctx.WithViaService(awsctx.WithMetadata(ctx, caller), "apigateway.amazonaws.com"), nil
	default:
		if roles == nil {
			return nil, &awswire.Error{Code: "InternalServerErrorException", Message: "API Gateway integration role resolver is not configured", StatusCode: http.StatusInternalServerError}
		}
		return roles.InvocationContext(ctx, credentialsARN, rest)
	}
}
