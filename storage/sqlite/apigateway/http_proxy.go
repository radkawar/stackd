package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) loadMethodRequestParameters(v *domain.MethodRecord) error {
	k := v.Key
	rows, err := r.q.ListMethodRequestParameters(r.ctx, sqlcgen.ListMethodRequestParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return err
	}
	v.RequestParameters = make(map[string]bool, len(rows))
	for _, row := range rows {
		v.RequestParameters[row.Name] = row.Required
	}
	return nil
}

func (w writer) putMethodRequestParameters(v domain.MethodRecord) error {
	k := v.Key
	if err := w.q.DeleteMethodRequestParameters(w.ctx, sqlcgen.DeleteMethodRequestParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}); err != nil {
		return err
	}
	for name, required := range v.RequestParameters {
		if err := w.q.PutMethodRequestParameters(w.ctx, sqlcgen.PutMethodRequestParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, Name: name, Required: required}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) loadHTTPProxyIntegration(k domain.MethodKey) (*apigatewayexec.HTTPProxyIntegration, error) {
	rows, err := r.q.ListHTTPProxyIntegrations(r.ctx, sqlcgen.ListHTTPProxyIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	row := rows[0]
	out := &apigatewayexec.HTTPProxyIntegration{URI: row.Uri, Method: row.IntegrationMethod, PathParameters: map[string]string{}}
	paths, err := r.q.ListHTTPProxyIntegrationPaths(r.ctx, sqlcgen.ListHTTPProxyIntegrationPathsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		out.PathParameters[path.Target] = path.Source
	}
	return out, nil
}

func (w writer) putHTTPProxyIntegration(k domain.MethodKey, v *apigatewayexec.HTTPProxyIntegration) error {
	if err := w.q.DeleteHTTPProxyIntegrations(w.ctx, sqlcgen.DeleteHTTPProxyIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	if err := w.q.PutHTTPProxyIntegrations(w.ctx, sqlcgen.PutHTTPProxyIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, Uri: v.URI, IntegrationMethod: v.Method}); err != nil {
		return err
	}
	for target, source := range v.PathParameters {
		if err := w.q.PutHTTPProxyIntegrationPaths(w.ctx, sqlcgen.PutHTTPProxyIntegrationPathsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, Target: target, Source: source}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) loadHTTPProxyRoute(k domain.DeploymentKey, resourceID, method string) (*apigatewayexec.HTTPProxyIntegration, error) {
	rows, err := r.q.ListHTTPProxyRoutes(r.ctx, sqlcgen.ListHTTPProxyRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	row := rows[0]
	out := &apigatewayexec.HTTPProxyIntegration{URI: row.Uri, Method: row.IntegrationMethod, PathParameters: map[string]string{}}
	paths, err := r.q.ListHTTPProxyRoutePaths(r.ctx, sqlcgen.ListHTTPProxyRoutePathsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method})
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		out.PathParameters[path.Target] = path.Source
	}
	return out, nil
}

func (w writer) putHTTPProxyRoute(k domain.DeploymentKey, resourceID, method string, v *apigatewayexec.HTTPProxyIntegration) error {
	if err := w.q.DeleteHTTPProxyRoutes(w.ctx, sqlcgen.DeleteHTTPProxyRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	if err := w.q.PutHTTPProxyRoutes(w.ctx, sqlcgen.PutHTTPProxyRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method, Uri: v.URI, IntegrationMethod: v.Method}); err != nil {
		return err
	}
	for target, source := range v.PathParameters {
		if err := w.q.PutHTTPProxyRoutePaths(w.ctx, sqlcgen.PutHTTPProxyRoutePathsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method, Target: target, Source: source}); err != nil {
			return err
		}
	}
	return nil
}
