// Package apigateway persists typed REST configuration in the shared SQLite transaction domain.
package apigateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func apiKey(partition, account, region, id string) domain.APIKey {
	return domain.APIKey{Scope: domain.Scope{Partition: partition, AccountID: account, Region: region}, ID: id}
}
func (r reader) api(v sqlcgen.ApigatewayApi) (domain.APIRecord, error) {
	out := domain.APIRecord{Key: domain.APIKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ApiID}, Name: v.Name, Description: v.Description, Version: v.Version, RootResourceID: v.RootResourceID, Created: v.Created, Disabled: v.Disabled, EffectiveDisabled: v.EffectiveDisabled}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	out.APIKeySource = v.ApiKeySource
	{
		rows, err := r.q.ListAPITags(r.ctx, sqlcgen.ListAPITagsParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID})
		if err != nil {
			return domain.APIRecord{}, err
		}
		out.Tags = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Tags[row.Key] = row.Value
		}
	}
	return out, nil
}
func (r reader) API(k domain.APIKey) (domain.APIRecord, error) {
	v, err := r.q.GetAPI(r.ctx, sqlcgen.GetAPIParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return domain.APIRecord{}, missing(err)
	}
	return r.api(v)
}
func (r reader) APIs(k domain.Scope) ([]domain.APIRecord, error) {
	rows, err := r.q.ListAPIs(r.ctx, sqlcgen.ListAPIsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.APIRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.api(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutAPI(v domain.APIRecord) error {
	k := v.Key
	if err := w.q.PutAPI(w.ctx, sqlcgen.PutAPIParams{CfnStackID: v.Ownership.StackID, CfnLogicalID: v.Ownership.LogicalID, CfnIncarnation: v.Ownership.Incarnation, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: v.Name, Description: v.Description, Version: v.Version, RootResourceID: v.RootResourceID, Created: v.Created, Disabled: v.Disabled, EffectiveDisabled: v.EffectiveDisabled, ApiKeySource: v.APIKeySource}); err != nil {
		return err
	}
	if err := w.q.DeleteAPITags(w.ctx, sqlcgen.DeleteAPITagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID}); err != nil {
		return err
	}
	for index, item := range v.Tags {
		if err := w.q.PutAPITags(w.ctx, sqlcgen.PutAPITagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Key: index, Value: item}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteAPI(k domain.APIKey) error {
	return w.q.DeleteAPI(w.ctx, sqlcgen.DeleteAPIParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
}
func (r reader) resource(v sqlcgen.ApigatewayResource) (domain.ResourceRecord, error) {
	out := domain.ResourceRecord{Key: domain.ResourceKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), ResourceID: v.ResourceID}, ParentID: v.ParentID, PathPart: v.PathPart, Path: v.Path}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	return out, nil
}
func (r reader) Resource(k domain.ResourceKey) (domain.ResourceRecord, error) {
	v, err := r.q.GetResource(r.ctx, sqlcgen.GetResourceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID})
	if err != nil {
		return domain.ResourceRecord{}, missing(err)
	}
	return r.resource(v)
}
func (r reader) Resources(k domain.APIKey) ([]domain.ResourceRecord, error) {
	rows, err := r.q.ListResources(r.ctx, sqlcgen.ListResourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ResourceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.resource(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutResource(v domain.ResourceRecord) error {
	k := v.Key
	if err := w.q.PutResource(w.ctx, sqlcgen.PutResourceParams{CfnStackID: v.Ownership.StackID, CfnLogicalID: v.Ownership.LogicalID, CfnIncarnation: v.Ownership.Incarnation, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, ParentID: v.ParentID, PathPart: v.PathPart, Path: v.Path}); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteResource(k domain.ResourceKey) error {
	return w.q.DeleteResource(w.ctx, sqlcgen.DeleteResourceParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID})
}
func (r reader) method(v sqlcgen.ApigatewayMethod) (domain.MethodRecord, error) {
	out := domain.MethodRecord{Key: domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), ResourceID: v.ResourceID}, HTTPMethod: v.HttpMethod}, AuthorizationType: v.AuthorizationType, AuthorizerID: v.AuthorizerID, OperationName: v.OperationName}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	out.APIKeyRequired = v.ApiKeyRequired
	{
		rows, err := r.q.ListMethodScopes(r.ctx, sqlcgen.ListMethodScopesParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID, ResourceID: out.Key.ResourceID, HttpMethod: out.Key.HTTPMethod})
		if err != nil {
			return domain.MethodRecord{}, err
		}
		out.Scopes = make([]string, 0, len(rows))
		for _, row := range rows {
			out.Scopes = append(out.Scopes, row.Scope)
		}
	}
	return out, nil
}
func (r reader) Method(k domain.MethodKey) (domain.MethodRecord, error) {
	v, err := r.q.GetMethod(r.ctx, sqlcgen.GetMethodParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return domain.MethodRecord{}, missing(err)
	}
	return r.method(v)
}
func (r reader) Methods(k domain.APIKey) ([]domain.MethodRecord, error) {
	rows, err := r.q.ListMethods(r.ctx, sqlcgen.ListMethodsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MethodRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.method(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutMethod(v domain.MethodRecord) error {
	k := v.Key
	if err := w.q.PutMethod(w.ctx, sqlcgen.PutMethodParams{CfnStackID: v.Ownership.StackID, CfnLogicalID: v.Ownership.LogicalID, CfnIncarnation: v.Ownership.Incarnation, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, AuthorizationType: v.AuthorizationType, AuthorizerID: v.AuthorizerID, OperationName: v.OperationName, ApiKeyRequired: v.APIKeyRequired}); err != nil {
		return err
	}
	if err := w.q.DeleteMethodScopes(w.ctx, sqlcgen.DeleteMethodScopesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}); err != nil {
		return err
	}
	for index, item := range v.Scopes {
		if err := w.q.PutMethodScopes(w.ctx, sqlcgen.PutMethodScopesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, Ordinal: int64(index), Scope: item}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteMethod(k domain.MethodKey) error {
	return w.q.DeleteMethod(w.ctx, sqlcgen.DeleteMethodParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
}
func (r reader) integration(v sqlcgen.ApigatewayIntegration) (domain.IntegrationRecord, error) {
	out := domain.IntegrationRecord{Key: domain.MethodKey{ResourceKey: domain.ResourceKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), ResourceID: v.ResourceID}, HTTPMethod: v.HttpMethod}, URI: v.Uri, TimeoutMillis: int32(v.TimeoutMillis)}
	out.CredentialsARN = v.CredentialsArn
	return out, nil
}
func (r reader) Integration(k domain.MethodKey) (domain.IntegrationRecord, error) {
	v, err := r.q.GetIntegration(r.ctx, sqlcgen.GetIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return domain.IntegrationRecord{}, missing(err)
	}
	return r.integration(v)
}
func (w writer) PutIntegration(v domain.IntegrationRecord) error {
	k := v.Key
	if err := w.q.PutIntegration(w.ctx, sqlcgen.PutIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, Uri: v.URI, TimeoutMillis: int64(v.TimeoutMillis), CredentialsArn: v.CredentialsARN}); err != nil {
		return err
	}
	return nil
}
func (w writer) DeleteIntegration(k domain.MethodKey) error {
	return w.q.DeleteIntegration(w.ctx, sqlcgen.DeleteIntegrationParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
}
func (r reader) authorizer(v sqlcgen.ApigatewayAuthorizer) (domain.AuthorizerRecord, error) {
	out := domain.AuthorizerRecord{Key: domain.AuthorizerKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), AuthorizerID: v.AuthorizerID}, Name: v.Name, AuthType: v.AuthType}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	out.URI = v.AuthorizerUri
	if v.AuthorizerType != "COGNITO_USER_POOLS" {
		out.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{ID: v.AuthorizerID, Type: v.AuthorizerType, FunctionARN: v.FunctionArn, CredentialsARN: v.CredentialsArn, PayloadVersion: "1.0", ValidationExpression: v.ValidationExpression, TTLSeconds: int32(v.TtlSeconds)}
		sources, err := r.q.ListAuthorizerIdentitySources(r.ctx, sqlcgen.ListAuthorizerIdentitySourcesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, AuthorizerID: v.AuthorizerID})
		if err != nil {
			return domain.AuthorizerRecord{}, err
		}
		for _, source := range sources {
			out.LambdaAuthorizer.IdentitySources = append(out.LambdaAuthorizer.IdentitySources, source.Source)
		}
	}
	{
		rows, err := r.q.ListAuthorizerPools(r.ctx, sqlcgen.ListAuthorizerPoolsParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID, AuthorizerID: out.Key.AuthorizerID})
		if err != nil {
			return domain.AuthorizerRecord{}, err
		}
		out.ProviderARNs = make([]string, 0, len(rows))
		for _, row := range rows {
			out.ProviderARNs = append(out.ProviderARNs, row.Arn)
		}
	}
	return out, nil
}
func (r reader) Authorizer(k domain.AuthorizerKey) (domain.AuthorizerRecord, error) {
	v, err := r.q.GetAuthorizer(r.ctx, sqlcgen.GetAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID})
	if err != nil {
		return domain.AuthorizerRecord{}, missing(err)
	}
	return r.authorizer(v)
}
func (r reader) Authorizers(k domain.APIKey) ([]domain.AuthorizerRecord, error) {
	rows, err := r.q.ListAuthorizers(r.ctx, sqlcgen.ListAuthorizersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AuthorizerRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.authorizer(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutAuthorizer(v domain.AuthorizerRecord) error {
	k := v.Key
	params := sqlcgen.PutAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID, Name: v.Name, AuthType: v.AuthType, AuthorizerType: "COGNITO_USER_POOLS", AuthorizerUri: v.URI}
	params.CfnStackID, params.CfnLogicalID, params.CfnIncarnation = v.Ownership.StackID, v.Ownership.LogicalID, v.Ownership.Incarnation
	if a := v.LambdaAuthorizer; a != nil {
		params.AuthorizerType, params.FunctionArn, params.ValidationExpression, params.TtlSeconds = a.Type, a.FunctionARN, a.ValidationExpression, int64(a.TTLSeconds)
		params.CredentialsArn = a.CredentialsARN
	}
	if err := w.q.PutAuthorizer(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.DeleteAuthorizerIdentitySources(w.ctx, sqlcgen.DeleteAuthorizerIdentitySourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID}); err != nil {
		return err
	}
	if a := v.LambdaAuthorizer; a != nil {
		for index, source := range a.IdentitySources {
			if err := w.q.PutAuthorizerIdentitySources(w.ctx, sqlcgen.PutAuthorizerIdentitySourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID, Ordinal: int64(index), Source: source}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteAuthorizerPools(w.ctx, sqlcgen.DeleteAuthorizerPoolsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID}); err != nil {
		return err
	}
	for index, item := range v.ProviderARNs {
		if err := w.q.PutAuthorizerPools(w.ctx, sqlcgen.PutAuthorizerPoolsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID, Ordinal: int64(index), Arn: item}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteAuthorizer(k domain.AuthorizerKey) error {
	return w.q.DeleteAuthorizer(w.ctx, sqlcgen.DeleteAuthorizerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, AuthorizerID: k.AuthorizerID})
}
func (r reader) deployment(v sqlcgen.ApigatewayDeployment) (domain.DeploymentRecord, error) {
	out := domain.DeploymentRecord{Key: domain.DeploymentKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), DeploymentID: v.DeploymentID}, Description: v.Description, Created: v.Created}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	out.APIKeySource = v.ApiKeySource
	resources, err := r.q.ListDeploymentResources(r.ctx, sqlcgen.ListDeploymentResourcesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, DeploymentID: v.DeploymentID})
	if err != nil {
		return domain.DeploymentRecord{}, err
	}
	out.Resources = make([]domain.DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		out.Resources = append(out.Resources, domain.DeploymentResource{ResourceID: resource.ResourceID, Path: resource.Path})
	}
	rows, err := r.q.ListDeploymentRoutes(r.ctx, sqlcgen.ListDeploymentRoutesParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID, DeploymentID: out.Key.DeploymentID})
	if err != nil {
		return domain.DeploymentRecord{}, err
	}
	out.Routes = make([]domain.DeploymentRoute, 0, len(rows))
	for _, row := range rows {
		route := domain.DeploymentRoute{ResourceID: row.ResourceID, HTTPMethod: row.HttpMethod, Path: row.Path, AuthorizationType: row.AuthorizationType, FunctionARN: row.FunctionArn, TimeoutMillis: int32(row.TimeoutMillis)}
		route.CredentialsARN = row.CredentialsArn
		route.APIKeyRequired = row.ApiKeyRequired
		if row.AuthorizerID != "" {
			route.LambdaAuthorizer = &apigatewayexec.LambdaAuthorizer{ID: row.AuthorizerID, Type: row.AuthorizerType, FunctionARN: row.AuthorizerFunctionArn, CredentialsARN: row.AuthorizerCredentialsArn, PayloadVersion: "1.0", ValidationExpression: row.AuthorizerValidationExpression, TTLSeconds: int32(row.AuthorizerTtlSeconds)}
			sources, err := r.q.ListRouteIdentitySources(r.ctx, sqlcgen.ListRouteIdentitySourcesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, DeploymentID: v.DeploymentID, ResourceID: row.ResourceID, HttpMethod: row.HttpMethod})
			if err != nil {
				return domain.DeploymentRecord{}, err
			}
			for _, source := range sources {
				route.LambdaAuthorizer.IdentitySources = append(route.LambdaAuthorizer.IdentitySources, source.Source)
			}
		}
		scopes, err := r.q.ListRouteScopes(r.ctx, sqlcgen.ListRouteScopesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, DeploymentID: v.DeploymentID, ResourceID: row.ResourceID, HttpMethod: row.HttpMethod})
		if err != nil {
			return domain.DeploymentRecord{}, err
		}
		for _, scope := range scopes {
			route.Scopes = append(route.Scopes, scope.Scope)
		}
		pools, err := r.q.ListRoutePools(r.ctx, sqlcgen.ListRoutePoolsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, DeploymentID: v.DeploymentID, ResourceID: row.ResourceID, HttpMethod: row.HttpMethod})
		if err != nil {
			return domain.DeploymentRecord{}, err
		}
		for _, pool := range pools {
			route.UserPoolARNs = append(route.UserPoolARNs, pool.Arn)
		}
		out.Routes = append(out.Routes, route)
	}
	return out, nil
}
func (r reader) Deployment(k domain.DeploymentKey) (domain.DeploymentRecord, error) {
	v, err := r.q.GetDeployment(r.ctx, sqlcgen.GetDeploymentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID})
	if err != nil {
		return domain.DeploymentRecord{}, missing(err)
	}
	return r.deployment(v)
}
func (r reader) Deployments(k domain.APIKey) ([]domain.DeploymentRecord, error) {
	rows, err := r.q.ListDeployments(r.ctx, sqlcgen.ListDeploymentsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DeploymentRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.deployment(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutDeployment(v domain.DeploymentRecord) error {
	k := v.Key
	if err := w.q.PutDeployment(w.ctx, sqlcgen.PutDeploymentParams{CfnStackID: v.Ownership.StackID, CfnLogicalID: v.Ownership.LogicalID, CfnIncarnation: v.Ownership.Incarnation, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, Description: v.Description, Created: v.Created, ApiKeySource: v.APIKeySource}); err != nil {
		return err
	}
	if err := w.q.DeleteDeploymentResources(w.ctx, sqlcgen.DeleteDeploymentResourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID}); err != nil {
		return err
	}
	for _, resource := range v.Resources {
		if err := w.q.PutDeploymentResources(w.ctx, sqlcgen.PutDeploymentResourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resource.ResourceID, Path: resource.Path}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteDeploymentRoutes(w.ctx, sqlcgen.DeleteDeploymentRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID}); err != nil {
		return err
	}
	for _, route := range v.Routes {
		params := sqlcgen.PutDeploymentRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: route.ResourceID, HttpMethod: route.HTTPMethod, Path: route.Path, AuthorizationType: route.AuthorizationType, FunctionArn: route.FunctionARN, TimeoutMillis: int64(route.TimeoutMillis)}
		params.CredentialsArn = route.CredentialsARN
		params.ApiKeyRequired = route.APIKeyRequired
		if a := route.LambdaAuthorizer; a != nil {
			params.AuthorizerID, params.AuthorizerType, params.AuthorizerFunctionArn, params.AuthorizerValidationExpression, params.AuthorizerTtlSeconds = a.ID, a.Type, a.FunctionARN, a.ValidationExpression, int64(a.TTLSeconds)
			params.AuthorizerCredentialsArn = a.CredentialsARN
		}
		if err := w.q.PutDeploymentRoutes(w.ctx, params); err != nil {
			return err
		}
		if a := route.LambdaAuthorizer; a != nil {
			for index, source := range a.IdentitySources {
				if err := w.q.PutRouteIdentitySources(w.ctx, sqlcgen.PutRouteIdentitySourcesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: route.ResourceID, HttpMethod: route.HTTPMethod, Ordinal: int64(index), Source: source}); err != nil {
					return err
				}
			}
		}
		for index, item := range route.Scopes {
			if err := w.q.PutRouteScopes(w.ctx, sqlcgen.PutRouteScopesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: route.ResourceID, HttpMethod: route.HTTPMethod, Ordinal: int64(index), Scope: item}); err != nil {
				return err
			}
		}
		for index, item := range route.UserPoolARNs {
			if err := w.q.PutRoutePools(w.ctx, sqlcgen.PutRoutePoolsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: route.ResourceID, HttpMethod: route.HTTPMethod, Ordinal: int64(index), Arn: item}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteDeployment(k domain.DeploymentKey) error {
	return w.q.DeleteDeployment(w.ctx, sqlcgen.DeleteDeploymentParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID})
}
func (r reader) stage(v sqlcgen.ApigatewayStage) (domain.StageRecord, error) {
	out := domain.StageRecord{Key: domain.StageKey{APIKey: apiKey(v.Partition, v.AccountID, v.Region, v.ApiID), Name: v.Name}, DeploymentID: v.DeploymentID, Description: v.Description, Created: v.Created, Updated: v.Updated}
	out.Ownership = domain.Ownership{StackID: v.CfnStackID, LogicalID: v.CfnLogicalID, Incarnation: v.CfnIncarnation}
	out.Incarnation = uint64(v.Incarnation)
	out.AccessLogs = apigatewayexec.AccessLogSettings{DestinationARN: v.AccessLogDestinationArn, Format: v.AccessLogFormat}
	{
		rows, err := r.q.ListStageTags(r.ctx, sqlcgen.ListStageTagsParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID, Name: out.Key.Name})
		if err != nil {
			return domain.StageRecord{}, err
		}
		out.Tags = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Tags[row.Key] = row.Value
		}
	}
	{
		rows, err := r.q.ListStageVariables(r.ctx, sqlcgen.ListStageVariablesParams{Partition: out.Key.Partition, AccountID: out.Key.AccountID, Region: out.Key.Region, ApiID: out.Key.ID, Name: out.Key.Name})
		if err != nil {
			return domain.StageRecord{}, err
		}
		out.Variables = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Variables[row.Key] = row.Value
		}
	}
	settings, err := r.q.ListMethodSettings(r.ctx, sqlcgen.ListMethodSettingsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApiID: v.ApiID, Stage: v.Name})
	if err != nil {
		return domain.StageRecord{}, err
	}
	out.MethodSettings = make(map[string]domain.MethodSettings, len(settings))
	for _, row := range settings {
		out.MethodSettings[row.MethodKey] = domain.MethodSettings{MetricsEnabled: row.MetricsEnabled, LoggingLevel: row.LoggingLevel, DataTraceEnabled: row.DataTraceEnabled}
	}
	return out, nil
}
func (r reader) Stage(k domain.StageKey) (domain.StageRecord, error) {
	v, err := r.q.GetStage(r.ctx, sqlcgen.GetStageParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name})
	if err != nil {
		return domain.StageRecord{}, missing(err)
	}
	return r.stage(v)
}
func (r reader) Stages(k domain.APIKey) ([]domain.StageRecord, error) {
	rows, err := r.q.ListStages(r.ctx, sqlcgen.ListStagesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.StageRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.stage(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutStage(v domain.StageRecord) error {
	k := v.Key
	if err := w.q.PutStage(w.ctx, sqlcgen.PutStageParams{Incarnation: int64(v.Incarnation), CfnStackID: v.Ownership.StackID, CfnLogicalID: v.Ownership.LogicalID, CfnIncarnation: v.Ownership.Incarnation, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name, DeploymentID: v.DeploymentID, Description: v.Description, Created: v.Created, Updated: v.Updated, AccessLogDestinationArn: v.AccessLogs.DestinationARN, AccessLogFormat: v.AccessLogs.Format}); err != nil {
		return err
	}
	if err := w.q.DeleteStageTags(w.ctx, sqlcgen.DeleteStageTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name}); err != nil {
		return err
	}
	for index, item := range v.Tags {
		if err := w.q.PutStageTags(w.ctx, sqlcgen.PutStageTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name, Key: index, Value: item}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteStageVariables(w.ctx, sqlcgen.DeleteStageVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name}); err != nil {
		return err
	}
	for index, item := range v.Variables {
		if err := w.q.PutStageVariables(w.ctx, sqlcgen.PutStageVariablesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name, Key: index, Value: item}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteMethodSettings(w.ctx, sqlcgen.DeleteMethodSettingsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Stage: k.Name}); err != nil {
		return err
	}
	for key, settings := range v.MethodSettings {
		if err := w.q.PutMethodSettings(w.ctx, sqlcgen.PutMethodSettingsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Stage: k.Name, MethodKey: key, MetricsEnabled: settings.MetricsEnabled, LoggingLevel: settings.LoggingLevel, DataTraceEnabled: settings.DataTraceEnabled}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteStage(k domain.StageKey) error {
	return w.q.DeleteStage(w.ctx, sqlcgen.DeleteStageParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, Name: k.Name})
}
func (r reader) Owner(id string) (domain.APIRecord, error) {
	v, err := r.q.GetOwner(r.ctx, id)
	if err != nil {
		return domain.APIRecord{}, missing(err)
	}
	return r.api(v)
}

func (r reader) AuthorizerCache(k domain.AuthorizerCacheKey) (domain.AuthorizerCacheRecord, error) {
	row, err := r.q.GetAuthorizerCache(r.ctx, sqlcgen.GetAuthorizerCacheParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, StageName: k.Name, AuthorizerID: k.AuthorizerID, IdentityKey: k.IdentityKey})
	if err != nil {
		return domain.AuthorizerCacheRecord{}, missing(err)
	}
	out := domain.AuthorizerCacheRecord{Key: k, ExpiresAt: row.ExpiresAt, Result: apigatewayexec.AuthorizerResult{PrincipalID: new(row.PrincipalID), PolicyDocument: row.PolicyDocument}}
	out.Result.UsageIdentifierKey = row.UsageIdentifierKey
	if err := json.Unmarshal(row.Context, &out.Result.Context); err != nil {
		return domain.AuthorizerCacheRecord{}, err
	}
	if row.IsAuthorized.Valid {
		out.Result.IsAuthorized = &row.IsAuthorized.Bool
	}
	return out, nil
}
func (w writer) PutAuthorizerCache(v domain.AuthorizerCacheRecord) error {
	k := v.Key
	contextJSON, err := json.Marshal(v.Result.Context)
	if err != nil {
		return err
	}
	authorized := sql.NullBool{}
	if v.Result.IsAuthorized != nil {
		authorized = sql.NullBool{Bool: *v.Result.IsAuthorized, Valid: true}
	}
	principal := ""
	if v.Result.PrincipalID != nil {
		principal = *v.Result.PrincipalID
	}
	return w.q.PutAuthorizerCache(w.ctx, sqlcgen.PutAuthorizerCacheParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, StageName: k.Name, AuthorizerID: k.AuthorizerID, IdentityKey: k.IdentityKey, PrincipalID: principal, PolicyDocument: v.Result.PolicyDocument, Context: contextJSON, IsAuthorized: authorized, ExpiresAt: v.ExpiresAt, UsageIdentifierKey: v.Result.UsageIdentifierKey})
}
func (w writer) DeleteStageAuthorizerCache(k domain.StageKey) error {
	return w.q.DeleteStageAuthorizerCache(w.ctx, sqlcgen.DeleteStageAuthorizerCacheParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, StageName: k.Name})
}
func (w writer) PruneAuthorizerCache(k domain.StageKey, now time.Time) error {
	return w.q.PruneAuthorizerCache(w.ctx, sqlcgen.PruneAuthorizerCacheParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, StageName: k.Name, ExpiresAt: now})
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}
