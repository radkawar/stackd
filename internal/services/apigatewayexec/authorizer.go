package apigatewayexec

import (
	"context"
	"encoding/json"
)

// LambdaAuthorizer is the deployed authorization configuration, independent of
// the backend integration's payload version and invocation permission.
// PayloadVersion is empty for WebSocket REQUEST authorizers and 1.0/2.0 for HTTP.
type LambdaAuthorizer struct {
	ID, Type, FunctionARN, PayloadVersion string
	CredentialsARN                        string
	IdentitySources                       []string
	ValidationExpression                  string
	TTLSeconds                            int32
	SimpleResponses                       bool
}

// AuthorizerResult is a successful Lambda authorizer protocol response. A deny
// policy or false simple response is cacheable; execution/protocol errors are not.
// Context retains JSON types until the integration payload projects them.
type AuthorizerResult struct {
	PrincipalID        *string
	PolicyDocument     json.RawMessage
	Context            map[string]json.RawMessage
	IsAuthorized       *bool
	UsageIdentifierKey string
}

// AuthorizerCache is implemented by each control plane's retained repository.
// The scope is API/stage/authorizer plus the ordered identity tuple. Load checks
// expiration against service time; Store starts the configured TTL at completion.
// Neither operation invokes Lambda or performs effects inside a transaction.
type AuthorizerCache interface {
	LoadAuthorizerResult(context.Context, *Route, string) (AuthorizerResult, bool, error)
	StoreAuthorizerResult(context.Context, *Route, string, AuthorizerResult) error
}
