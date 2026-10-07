// Package apigatewayexec owns the HTTP execution boundary shared by REST and HTTP APIs.
package apigatewayexec

import (
	"context"
	"errors"
)

// ErrUnknownAPI permits the shared endpoint to try the other API control plane.
// Missing stages and routes in an existing API must not return this sentinel.
var ErrUnknownAPI = errors.New("API ID is not owned by this control plane")

// Route is an immutable deployed route selected by a control-plane owner.
// Editing an undeployed resource must not alter this value for an existing stage.
type Route struct {
	Partition, AccountID, Region        string
	APIID, APIName, Stage, DeploymentID string
	ProtocolType                        string
	DetailedMetricsEnabled              bool
	Logging                             LoggingSettings
	ResourceID, ResourcePath, RouteKey  string
	FunctionARN, PayloadVersion         string
	IntegrationCredentialsARN           string
	AuthorizationType                   string
	APIKeyRequired                      bool
	APIKeySource                        string
	Issuer                              string
	Audiences, Scopes, UserPoolARNs     []string
	StageVariables, PathParameters      map[string]string
	LambdaAuthorizer                    *LambdaAuthorizer
	WebSocketResponseEnabled            bool
	IntegrationTimeoutMillis            int32
	Mock                                *MockIntegration
	BinaryMediaTypes                    []string
	GatewayResponses                    map[string]GatewayResponse
}

// Resolver reads a deployed snapshot without performing external effects.
// It resolves globally unique API IDs to their retained account/region owner;
// callers must still enforce the route's invocation authorization.
type Resolver interface {
	AuthorizerCache
	Resolve(context.Context, string, string, string, string) (*Route, error)
}
