// Package apigatewayv2 owns retained HTTP and WebSocket API configuration and deployments.
package apigatewayv2

import (
	"context"
	"errors"
	"time"

	"stackd/internal/services/apigatewayexec"
)

var ErrNotFound = errors.New("API Gateway V2 resource not found")

type Scope struct{ Partition, AccountID, Region string }
type APIKey struct {
	Scope
	ID string
}
type ResourceKey struct {
	APIKey
	ID string
}

type APIRecord struct {
	Key                                    APIKey
	Owner                                  ResourceOwner
	Name, Description, Version             string
	ProtocolType, RouteSelectionExpression string
	Disabled                               bool
	Created                                time.Time
	Tags                                   map[string]string
}
type IntegrationRecord struct {
	Key                              ResourceKey
	Owner                            ResourceOwner
	Description, URI, PayloadVersion string
	CredentialsARN                   string
	TimeoutMillis                    int32
	PassthroughBehavior              string
}
type AuthorizerRecord struct {
	Key              ResourceKey
	Owner            ResourceOwner
	Name, Issuer     string
	Audiences        []string
	URI              string
	LambdaAuthorizer *apigatewayexec.LambdaAuthorizer
}
type RouteRecord struct {
	Key                                                              ResourceKey
	Owner                                                            ResourceOwner
	RouteKey, Target, AuthorizationType, AuthorizerID, OperationName string
	RouteResponseSelectionExpression                                 string
	Scopes                                                           []string
}
type RouteResponseRecord struct {
	Key         ResourceKey
	Owner       ResourceOwner
	RouteID     string
	ResponseKey string
}

// RouteSettings retains omitted route values separately from explicit false/OFF.
// Stage defaults are rendered with protocol defaults when these fields are unset.
type RouteSettings struct {
	DetailedMetricsEnabled *bool
	LoggingLevel           string
	DataTraceEnabled       *bool
}
type StageRecord struct {
	Key                                                    ResourceKey
	Owner                                                  ResourceOwner
	Description, DeploymentID, LastDeploymentStatusMessage string
	AutoDeploy                                             bool
	Created, Updated                                       time.Time
	Variables, Tags                                        map[string]string
	DefaultRouteSettings                                   RouteSettings
	RouteSettings                                          map[string]RouteSettings
	AccessLogSettings                                      apigatewayexec.AccessLogSettings
}
type DeploymentRecord struct {
	Key                      ResourceKey
	Owner                    ResourceOwner
	Description              string
	RouteSelectionExpression string
	AutoDeployed             bool
	Created                  time.Time
}

// DeployedRoute freezes every execution-relevant draft field. It never follows
// live integration or authorizer references after a deployment is created.
type DeployedRoute struct {
	Key                                                                       ResourceKey // ID is the deployment ID.
	RouteID, RouteKey, FunctionARN, PayloadVersion, AuthorizationType, Issuer string
	CredentialsARN                                                            string
	Audiences, Scopes                                                         []string
	LambdaAuthorizer                                                          *apigatewayexec.LambdaAuthorizer
	WebSocketResponseEnabled                                                  bool
	TimeoutMillis                                                             int32
}

// AuthorizerCacheKey retains the ordered identity tuple exactly as resolved.
type AuthorizerCacheKey struct {
	Stage                     ResourceKey
	AuthorizerID, IdentityKey string
}
type AuthorizerCacheRecord struct {
	Key AuthorizerCacheKey
	apigatewayexec.AuthorizerResult
	ExpiresAt time.Time
}

type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	DomainReader
	Context() context.Context
	API(APIKey) (APIRecord, error)
	APIByID(string) (APIRecord, error)
	APIs(Scope) ([]APIRecord, error)
	Integration(ResourceKey) (IntegrationRecord, error)
	Integrations(APIKey) ([]IntegrationRecord, error)
	Authorizer(ResourceKey) (AuthorizerRecord, error)
	Authorizers(APIKey) ([]AuthorizerRecord, error)
	Route(ResourceKey) (RouteRecord, error)
	Routes(APIKey) ([]RouteRecord, error)
	RouteResponse(ResourceKey) (RouteResponseRecord, error)
	RouteResponses(ResourceKey) ([]RouteResponseRecord, error) // ID is the route ID.
	Stage(ResourceKey) (StageRecord, error)
	Stages(APIKey) ([]StageRecord, error)
	Deployment(ResourceKey) (DeploymentRecord, error)
	Deployments(APIKey) ([]DeploymentRecord, error)
	DeployedRoutes(ResourceKey) ([]DeployedRoute, error)
	AuthorizerCache(AuthorizerCacheKey) (AuthorizerCacheRecord, error)
}
type Transaction interface {
	Reader
	DomainTransaction
	PutAPI(APIRecord) error
	DeleteAPI(APIKey) error
	PutIntegration(IntegrationRecord) error
	DeleteIntegration(ResourceKey) error
	PutAuthorizer(AuthorizerRecord) error
	DeleteAuthorizer(ResourceKey) error
	PutRoute(RouteRecord) error
	DeleteRoute(ResourceKey) error
	PutRouteResponse(RouteResponseRecord) error
	DeleteRouteResponse(ResourceKey) error
	PutStage(StageRecord) error
	DeleteStage(ResourceKey) error
	PutDeployment(DeploymentRecord) error
	DeleteDeployment(ResourceKey) error
	PutDeployedRoute(DeployedRoute) error
	PutAuthorizerCache(AuthorizerCacheRecord) error
	DeleteStageAuthorizerCache(ResourceKey) error
	PruneAuthorizerCache(APIKey, time.Time) error
}
