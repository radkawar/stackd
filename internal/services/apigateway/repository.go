// Package apigateway owns regional REST API configuration and immutable deployments.
package apigateway

import (
	"context"
	"errors"
	"stackd/internal/services/apigatewayexec"
	"time"
)

var ErrNotFound = errors.New("API Gateway resource not found")

type Scope struct{ Partition, AccountID, Region string }

type AccountRecord struct {
	Scope
	CloudWatchRoleARN string
}
type APIKey struct {
	Scope
	ID string
}
type ResourceKey struct {
	APIKey
	ResourceID string
}
type MethodKey struct {
	ResourceKey
	HTTPMethod string
}
type AuthorizerKey struct {
	APIKey
	AuthorizerID string
}
type DeploymentKey struct {
	APIKey
	DeploymentID string
}
type StageKey struct {
	APIKey
	Name string
}

type APIRecord struct {
	Key                                        APIKey
	Name, Description, Version, RootResourceID string
	Created                                    time.Time
	Disabled                                   bool
	EffectiveDisabled                          bool
	APIKeySource                               string
	Tags                                       map[string]string
}
type ResourceRecord struct {
	Key                      ResourceKey
	ParentID, PathPart, Path string
}
type MethodRecord struct {
	Key                                            MethodKey
	AuthorizationType, AuthorizerID, OperationName string
	Scopes                                         []string
	APIKeyRequired                                 bool
}
type IntegrationRecord struct {
	Key            MethodKey
	URI            string
	CredentialsARN string
	TimeoutMillis  int32
}
type AuthorizerRecord struct {
	Key              AuthorizerKey
	Name, AuthType   string
	ProviderARNs     []string
	URI              string
	LambdaAuthorizer *apigatewayexec.LambdaAuthorizer
}

// DeploymentRoute is an owned snapshot, deliberately independent of mutable
// resource, method, integration and authorizer rows (including their deletion).
type DeploymentRoute struct {
	ResourceID, Path, HTTPMethod, AuthorizationType, FunctionARN string
	CredentialsARN                                               string
	Scopes, UserPoolARNs                                         []string
	TimeoutMillis                                                int32
	LambdaAuthorizer                                             *apigatewayexec.LambdaAuthorizer
	APIKeyRequired                                               bool
}
type DeploymentResource struct{ ResourceID, Path string }
type DeploymentRecord struct {
	Key          DeploymentKey
	Description  string
	Created      time.Time
	APIKeySource string
	Resources    []DeploymentResource
	Routes       []DeploymentRoute
}

type MethodSettings struct {
	MetricsEnabled   bool
	LoggingLevel     string
	DataTraceEnabled bool
}
type StageRecord struct {
	Key                       StageKey
	DeploymentID, Description string
	Created, Updated          time.Time
	Variables, Tags           map[string]string
	MethodSettings            map[string]MethodSettings
	AccessLogs                apigatewayexec.AccessLogSettings
}

type AuthorizerCacheKey struct {
	StageKey
	AuthorizerID, IdentityKey string
}
type AuthorizerCacheRecord struct {
	Key       AuthorizerCacheKey
	Result    apigatewayexec.AuthorizerResult
	ExpiresAt time.Time
}

// Repository joins configuration and completion events in the shared native
// transaction domain. Callbacks must not perform external effects.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	MetricReader
	Context() context.Context
	Account(Scope) (AccountRecord, error)
	API(APIKey) (APIRecord, error)
	APIs(Scope) ([]APIRecord, error)
	// Owner resolves a globally unique API ID without borrowing caller scope.
	Owner(string) (APIRecord, error)
	Resource(ResourceKey) (ResourceRecord, error)
	Resources(APIKey) ([]ResourceRecord, error)
	Method(MethodKey) (MethodRecord, error)
	Methods(APIKey) ([]MethodRecord, error)
	Integration(MethodKey) (IntegrationRecord, error)
	Authorizer(AuthorizerKey) (AuthorizerRecord, error)
	Authorizers(APIKey) ([]AuthorizerRecord, error)
	Deployment(DeploymentKey) (DeploymentRecord, error)
	Deployments(APIKey) ([]DeploymentRecord, error)
	Stage(StageKey) (StageRecord, error)
	Stages(APIKey) ([]StageRecord, error)
	AuthorizerCache(AuthorizerCacheKey) (AuthorizerCacheRecord, error)
	ClientKey(ClientKey) (ClientKeyRecord, error)
	ClientKeyByValue(Scope, string) (ClientKeyRecord, error)
	ClientKeys(Scope) ([]ClientKeyRecord, error)
	UsagePlan(PlanKey) (UsagePlanRecord, error)
	UsagePlans(Scope) ([]UsagePlanRecord, error)
	UsagePlansForKey(ClientKey) ([]UsagePlanRecord, error)
	UsagePlanMembership(PlanKey, string) (UsagePlanMembership, error)
	UsagePlanKeys(PlanKey) ([]ClientKeyRecord, error)
	// UsageCount counts admitted requests in UTC days [start, end).
	UsageCount(plan PlanKey, clientKeyID string, start, end time.Time) (int64, error)
}
type Transaction interface {
	Reader
	MetricWriter
	PutAccount(AccountRecord) error
	PutAPI(APIRecord) error
	DeleteAPI(APIKey) error
	PutResource(ResourceRecord) error
	DeleteResource(ResourceKey) error
	PutMethod(MethodRecord) error
	DeleteMethod(MethodKey) error
	PutIntegration(IntegrationRecord) error
	DeleteIntegration(MethodKey) error
	PutAuthorizer(AuthorizerRecord) error
	DeleteAuthorizer(AuthorizerKey) error
	PutDeployment(DeploymentRecord) error
	DeleteDeployment(DeploymentKey) error
	PutStage(StageRecord) error
	DeleteStage(StageKey) error
	PutAuthorizerCache(AuthorizerCacheRecord) error
	DeleteStageAuthorizerCache(StageKey) error
	PruneAuthorizerCache(StageKey, time.Time) error
	PutClientKey(ClientKeyRecord) error
	DeleteClientKey(ClientKey) error
	PutUsagePlan(UsagePlanRecord) error
	DeleteUsagePlan(PlanKey) error
	PutUsagePlanMembership(UsagePlanMembership) error
	DeleteUsagePlanMembership(PlanKey, string) error
	IncrementUsage(plan PlanKey, clientKeyID string, day time.Time) error
}
