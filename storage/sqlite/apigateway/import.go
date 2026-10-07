package apigateway

import (
	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite/apigateway/internal/sqlcgen"
)

func (r reader) loadAPIImport(v *domain.APIRecord) error {
	k := v.Key
	rows, err := r.q.ListBinaryMediaTypes(r.ctx, sqlcgen.ListBinaryMediaTypesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return err
	}
	for _, row := range rows {
		v.BinaryMediaTypes = append(v.BinaryMediaTypes, row.MediaType)
	}
	responses, err := r.q.ListGatewayResponses(r.ctx, sqlcgen.ListGatewayResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID})
	if err != nil {
		return err
	}
	v.GatewayResponses = map[string]apigatewayexec.GatewayResponse{}
	for _, row := range responses {
		kind := row.ResponseType
		response := apigatewayexec.GatewayResponse{StatusCode: int(row.StatusCode), Headers: map[string]string{}, Templates: map[string]string{}}
		headers, err := r.q.ListGatewayHeaders(r.ctx, sqlcgen.ListGatewayHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResponseType: kind})
		if err != nil {
			return err
		}
		for _, header := range headers {
			response.Headers[header.Name] = header.Value
		}
		templates, err := r.q.ListGatewayTemplates(r.ctx, sqlcgen.ListGatewayTemplatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResponseType: kind})
		if err != nil {
			return err
		}
		for _, template := range templates {
			response.Templates[template.MediaType] = template.Template
		}
		v.GatewayResponses[kind] = response
	}
	return nil
}

func (w writer) putAPIImport(v domain.APIRecord) error {
	k := v.Key
	if err := w.q.DeleteBinaryMediaTypes(w.ctx, sqlcgen.DeleteBinaryMediaTypesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID}); err != nil {
		return err
	}
	for i, media := range v.BinaryMediaTypes {
		p := sqlcgen.PutBinaryMediaTypesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID}
		p.Ordinal = int64(i)
		p.MediaType = media
		if err := w.q.PutBinaryMediaTypes(w.ctx, p); err != nil {
			return err
		}
	}
	if err := w.q.DeleteGatewayResponses(w.ctx, sqlcgen.DeleteGatewayResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID}); err != nil {
		return err
	}
	for kind, response := range v.GatewayResponses {
		p := sqlcgen.PutGatewayResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID}
		p.ResponseType = kind
		p.StatusCode = int64(response.StatusCode)
		if err := w.q.PutGatewayResponses(w.ctx, p); err != nil {
			return err
		}
		for name, value := range response.Headers {
			p := sqlcgen.PutGatewayHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResponseType: kind}
			p.Name, p.Value = name, value
			if err := w.q.PutGatewayHeaders(w.ctx, p); err != nil {
				return err
			}
		}
		for media, template := range response.Templates {
			p := sqlcgen.PutGatewayTemplatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResponseType: kind}
			p.MediaType, p.Template = media, template
			if err := w.q.PutGatewayTemplates(w.ctx, p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r reader) loadMockIntegration(k domain.MethodKey) (*apigatewayexec.MockIntegration, error) {
	rows, err := r.q.ListMockIntegrations(r.ctx, sqlcgen.ListMockIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	row := rows[0]
	out := &apigatewayexec.MockIntegration{StatusCode: int(row.StatusCode), Body: row.Body, Headers: map[string]string{}}
	headers, err := r.q.ListMockIntegrationHeaders(r.ctx, sqlcgen.ListMockIntegrationHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return nil, err
	}
	for _, header := range headers {
		out.Headers[header.Name] = header.Value
	}
	return out, nil
}

func (w writer) putMockIntegration(k domain.MethodKey, v *apigatewayexec.MockIntegration) error {
	if err := w.q.DeleteMockIntegrations(w.ctx, sqlcgen.DeleteMockIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	p := sqlcgen.PutMockIntegrationsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}
	p.StatusCode, p.Body = int64(v.StatusCode), v.Body
	if err := w.q.PutMockIntegrations(w.ctx, p); err != nil {
		return err
	}
	for name, value := range v.Headers {
		p := sqlcgen.PutMockIntegrationHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}
		p.Name, p.Value = name, value
		if err := w.q.PutMockIntegrationHeaders(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) loadMockRoute(k domain.DeploymentKey, resourceID, method string) (*apigatewayexec.MockIntegration, error) {
	rows, err := r.q.ListMockRoutes(r.ctx, sqlcgen.ListMockRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	row := rows[0]
	out := &apigatewayexec.MockIntegration{StatusCode: int(row.StatusCode), Body: row.Body, Headers: map[string]string{}}
	headers, err := r.q.ListMockRouteHeaders(r.ctx, sqlcgen.ListMockRouteHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method})
	if err != nil {
		return nil, err
	}
	for _, header := range headers {
		out.Headers[header.Name] = header.Value
	}
	return out, nil
}

func (w writer) putMockRoute(k domain.DeploymentKey, resourceID, method string, v *apigatewayexec.MockIntegration) error {
	if err := w.q.DeleteMockRoutes(w.ctx, sqlcgen.DeleteMockRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method}); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	p := sqlcgen.PutMockRoutesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method}
	p.StatusCode, p.Body = int64(v.StatusCode), v.Body
	if err := w.q.PutMockRoutes(w.ctx, p); err != nil {
		return err
	}
	for name, value := range v.Headers {
		p := sqlcgen.PutMockRouteHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, DeploymentID: k.DeploymentID, ResourceID: resourceID, HttpMethod: method}
		p.Name, p.Value = name, value
		if err := w.q.PutMockRouteHeaders(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) loadMethodResponses(v *domain.MethodRecord) error {
	k := v.Key
	rows, err := r.q.ListMethodResponses(r.ctx, sqlcgen.ListMethodResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod})
	if err != nil {
		return err
	}
	v.Responses = map[string]domain.MethodResponse{}
	for _, row := range rows {
		status := row.StatusCode
		response := domain.MethodResponse{Headers: map[string]bool{}}
		headers, err := r.q.ListMethodResponseHeaders(r.ctx, sqlcgen.ListMethodResponseHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, StatusCode: status})
		if err != nil {
			return err
		}
		for _, header := range headers {
			response.Headers[header.Name] = header.Required
		}
		v.Responses[status] = response
	}
	return nil
}

func (w writer) putMethodResponses(v domain.MethodRecord) error {
	k := v.Key
	if err := w.q.DeleteMethodResponses(w.ctx, sqlcgen.DeleteMethodResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}); err != nil {
		return err
	}
	for status, response := range v.Responses {
		p := sqlcgen.PutMethodResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod}
		p.StatusCode = status
		if err := w.q.PutMethodResponses(w.ctx, p); err != nil {
			return err
		}
		for name, required := range response.Headers {
			p := sqlcgen.PutMethodResponseHeadersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ApiID: k.ID, ResourceID: k.ResourceID, HttpMethod: k.HTTPMethod, StatusCode: status}
			p.Name, p.Required = name, required
			if err := w.q.PutMethodResponseHeaders(w.ctx, p); err != nil {
				return err
			}
		}
	}
	return nil
}
