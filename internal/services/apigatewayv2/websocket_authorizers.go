package apigatewayv2

import (
	"regexp"

	"github.com/dlclark/regexp2"
	api "stackd/internal/awsapi/apigatewayv2"
)

var webSocketAuthorizerSource = regexp.MustCompile(`^(route\.request\.(header|querystring)|context|stageVariables)\.[a-zA-Z0-9._-]+$`)

func validateWebSocketAuthorizer(in *api.CreateAuthorizerInput) error {
	if value(in.AuthorizerType) != "REQUEST" {
		return bad("Invalid authorizer type. Only REQUEST authorizer type is supported on WEBSOCKET protocol Apis.")
	}
	if in.AuthorizerPayloadFormatVersion != nil {
		return bad("AuthorizerPayloadFormatVersion cannot be set for WEBSOCKET protocol Apis.")
	}
	if in.AuthorizerResultTtlInSeconds != nil {
		return bad("AuthorizerResultTtlInSeconds cannot be set for WEBSOCKET protocol Apis.")
	}
	if in.EnableSimpleResponses != nil {
		return bad("EnableSimpleResponses cannot be set for WEBSOCKET protocol Apis.")
	}
	if in.JwtConfiguration != nil {
		return bad("JwtConfiguration cannot be set for WEBSOCKET protocol Apis.")
	}
	if in.AuthorizerCredentialsArn != nil && !authorizerRoleARN.MatchString(value(in.AuthorizerCredentialsArn)) {
		return bad("Invalid role ARN")
	}
	if _, err := authorizerFunctionARN(value(in.AuthorizerUri)); err != nil {
		return err
	}
	for _, expression := range in.IdentitySource {
		if len(in.IdentitySource) == 1 && expression == "" {
			break
		}
		if !webSocketAuthorizerSource.MatchString(string(expression)) {
			return bad("Invalid request identity source expression: " + string(expression) + ". The sources must be separated by comma, and each source must be either a request parameter, matching 'route.request.querystring|header.[a-zA-Z0-9._-]+', or a stage variable, matching 'stageVariables.[a-zA-Z0-9._-]+', or a context parameter, matching 'context.[a-zA-Z0-9._-]+'")
		}
	}
	if in.IdentityValidationExpression != nil {
		expression := value(in.IdentityValidationExpression)
		if expression == "" {
			return bad("IdentityValidationExpression must not be empty.")
		}
		if _, err := regexp2.Compile(expression, regexp2.None); err != nil {
			return bad("Invalid validation expression: " + expression)
		}
	}
	return nil
}
