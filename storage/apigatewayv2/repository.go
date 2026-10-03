// Package apigatewayv2 exposes service-owned API Gateway storage contracts.
package apigatewayv2

import (
	"stackd/internal/services/apigatewayexec"
	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/memory"
)

type (
	Scope                 = domain.Scope
	APIKey                = domain.APIKey
	ResourceKey           = domain.ResourceKey
	APIRecord             = domain.APIRecord
	IntegrationRecord     = domain.IntegrationRecord
	AuthorizerRecord      = domain.AuthorizerRecord
	AuthorizerCacheKey    = domain.AuthorizerCacheKey
	AuthorizerCacheRecord = domain.AuthorizerCacheRecord
	LambdaAuthorizer      = apigatewayexec.LambdaAuthorizer
	AuthorizerResult      = apigatewayexec.AuthorizerResult
	RouteRecord           = domain.RouteRecord
	RouteSettings         = domain.RouteSettings
	StageRecord           = domain.StageRecord
	DeploymentRecord      = domain.DeploymentRecord
	DeployedRoute         = domain.DeployedRoute
	Repository            = domain.Repository
	Reader                = domain.Reader
	Transaction           = domain.Transaction
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
