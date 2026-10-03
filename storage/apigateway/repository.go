// Package apigateway exposes service-owned API Gateway storage contracts.
package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/memory"
)

type (
	Scope                 = domain.Scope
	AccountRecord         = domain.AccountRecord
	APIKey                = domain.APIKey
	ResourceKey           = domain.ResourceKey
	MethodKey             = domain.MethodKey
	AuthorizerKey         = domain.AuthorizerKey
	DeploymentKey         = domain.DeploymentKey
	StageKey              = domain.StageKey
	APIRecord             = domain.APIRecord
	ResourceRecord        = domain.ResourceRecord
	MethodRecord          = domain.MethodRecord
	IntegrationRecord     = domain.IntegrationRecord
	AuthorizerRecord      = domain.AuthorizerRecord
	AuthorizerCacheKey    = domain.AuthorizerCacheKey
	AuthorizerCacheRecord = domain.AuthorizerCacheRecord
	LambdaAuthorizer      = apigatewayexec.LambdaAuthorizer
	AuthorizerResult      = apigatewayexec.AuthorizerResult
	DeploymentRoute       = domain.DeploymentRoute
	DeploymentResource    = domain.DeploymentResource
	DeploymentRecord      = domain.DeploymentRecord
	StageRecord           = domain.StageRecord
	MethodSettings        = domain.MethodSettings
	MetricPublicationKey  = domain.MetricPublicationKey
	MetricSample          = domain.MetricSample
	Repository            = domain.Repository
	Reader                = domain.Reader
	Transaction           = domain.Transaction
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
