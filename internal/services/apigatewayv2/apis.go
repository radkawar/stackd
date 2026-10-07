package apigatewayv2

import (
	api "stackd/internal/awsapi/apigatewayv2"
	"strings"
)

func (s *Service) apiOutput(v APIRecord) api.Api {
	out := api.Api{CreatedDate: new(v.Created)}
	endpoint := s.endpoint
	if v.ProtocolType == "WEBSOCKET" {
		endpoint = strings.Replace(endpoint, "https://", "wss://", 1)
		endpoint = strings.Replace(endpoint, "http://", "ws://", 1)
	}
	text(&out.ApiEndpoint, endpoint+"/_stackd/execute-api/"+v.Key.ID)
	text(&out.ApiId, v.Key.ID)
	text(&out.Name, v.Name)
	text(&out.ProtocolType, v.ProtocolType)
	text(&out.RouteSelectionExpression, v.RouteSelectionExpression)
	text(&out.ApiKeySelectionExpression, "$request.header.x-api-key")
	text(&out.IpAddressType, "ipv4")
	flag(&out.DisableExecuteApiEndpoint, v.Disabled)
	if v.Description != "" {
		text(&out.Description, v.Description)
	}
	if v.Version != "" {
		text(&out.Version, v.Version)
	}
	stringMap(&out.Tags, v.Tags)
	return out
}
func validateAPI(in *api.CreateApiInput) error {
	if value(in.Name) == "" {
		return bad("Name is required")
	}
	switch value(in.ProtocolType) {
	case "HTTP":
		if in.RouteSelectionExpression != nil && value(in.RouteSelectionExpression) != "$request.method $request.path" {
			return unsupported("HTTP APIs require the default route selection expression")
		}
	case "WEBSOCKET":
		if _, err := compileWebSocketSelection(value(in.RouteSelectionExpression)); err != nil {
			return err
		}
	default:
		return bad("ProtocolType must be HTTP or WEBSOCKET")
	}
	// TODO: Comeback implement CORS, quick-create and additional API settings.
	if in.CorsConfiguration != nil || in.CredentialsArn != nil || in.Target != nil || in.RouteKey != nil || boolean(in.DisableSchemaValidation) || in.ApiKeySelectionExpression != nil && value(in.ApiKeySelectionExpression) != "$request.header.x-api-key" || in.IpAddressType != nil && value(in.IpAddressType) != "ipv4" {
		return unsupported("CORS, quick-create, credentials and nonstandard API key selection or address settings are not implemented")
	}
	return validTags(mapOf(in.Tags))
}
func (s *Service) createAPI(tx Transaction, in *api.CreateApiInput) (*api.CreateApiOutput, error) {
	if err := s.authorize(tx, "POST", "/apis", nil, mapOf(in.Tags), nil); err != nil {
		return nil, err
	}
	if err := validateAPI(in); err != nil {
		return nil, err
	}
	if v, found, err := recoverOwnedResource(tx, scopeFor(tx.Context()), tx.APIs); err != nil {
		return nil, err
	} else if found {
		return new(api.CreateApiOutput(s.apiOutput(v))), nil
	}
	id, err := controlID()
	if err != nil {
		return nil, err
	}
	v := APIRecord{Key: APIKey{scopeFor(tx.Context()), id}, Name: value(in.Name), Description: value(in.Description), Version: value(in.Version), Disabled: boolean(in.DisableExecuteApiEndpoint), Created: s.clock.Now(), Tags: mapOf(in.Tags)}
	v.ProtocolType = value(in.ProtocolType)
	v.RouteSelectionExpression = value(in.RouteSelectionExpression)
	if v.ProtocolType == "HTTP" {
		v.RouteSelectionExpression = "$request.method $request.path"
	}
	if err := tx.PutAPI(v); err != nil {
		return nil, err
	}
	return new(api.CreateApiOutput(s.apiOutput(v))), nil
}
func (s *Service) getAPI(tx Transaction, in *api.GetApiInput) (*api.GetApiOutput, error) {
	v, err := s.ownedAPI(tx, "GET", value(in.ApiId), "")
	if err != nil {
		return nil, err
	}
	return new(api.GetApiOutput(s.apiOutput(v))), nil
}
func (s *Service) getAPIs(tx Transaction, in *api.GetApisInput) (*api.GetApisOutput, error) {
	if err := s.authorize(tx, "GET", "/apis", nil, nil, nil); err != nil {
		return nil, err
	}
	rows, err := tx.APIs(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/apis"), func(v APIRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.GetApisOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, s.apiOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.Api{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}
func (s *Service) updateAPI(tx Transaction, in *api.UpdateApiInput) (*api.UpdateApiOutput, error) {
	v, err := s.ownedAPI(tx, "PATCH", value(in.ApiId), "")
	if err != nil {
		return nil, err
	}
	check := api.CreateApiInput{Name: new(api.StringWithLengthBetween1And128(v.Name)), ProtocolType: new(api.ProtocolType(v.ProtocolType)), CorsConfiguration: in.CorsConfiguration, CredentialsArn: in.CredentialsArn, Target: in.Target, RouteKey: in.RouteKey, DisableSchemaValidation: in.DisableSchemaValidation, ApiKeySelectionExpression: in.ApiKeySelectionExpression, RouteSelectionExpression: new(api.SelectionExpression(v.RouteSelectionExpression)), IpAddressType: in.IpAddressType}
	if in.RouteSelectionExpression != nil {
		check.RouteSelectionExpression = in.RouteSelectionExpression
	}
	if in.Name != nil {
		check.Name = in.Name
	}
	if err := validateAPI(&check); err != nil {
		return nil, err
	}
	if in.Name != nil {
		v.Name = value(in.Name)
	}
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if in.Version != nil {
		v.Version = value(in.Version)
	}
	if in.DisableExecuteApiEndpoint != nil {
		v.Disabled = boolean(in.DisableExecuteApiEndpoint)
	}
	v.RouteSelectionExpression = value(check.RouteSelectionExpression)
	if err := tx.PutAPI(v); err != nil {
		return nil, err
	}
	if err := s.autoDeploy(tx, v.Key); err != nil {
		return nil, err
	}
	return new(api.UpdateApiOutput(s.apiOutput(v))), nil
}
func (s *Service) deleteAPI(tx Transaction, in *api.DeleteApiInput) (*api.DeleteApiOutput, error) {
	v, err := s.ownedAPI(tx, "DELETE", value(in.ApiId), "")
	if err != nil {
		return nil, err
	}
	if err := tx.DeleteAPI(v.Key); err != nil {
		return nil, err
	}
	return &api.DeleteApiOutput{}, nil
}
