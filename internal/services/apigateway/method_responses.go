package apigateway

import (
	api "stackd/internal/awsapi/apigateway"
	"strings"
)

func (s *Service) putMethodResponse(tx Transaction, in *api.PutMethodResponseRequest) (*api.MethodResponse, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PUT", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/responses/"+string(value(in.StatusCode)))
	if err != nil {
		return nil, err
	}
	if _, err := responseStatus(string(value(in.StatusCode))); err != nil {
		return nil, err
	}
	if len(in.ResponseModels) != 0 {
		return nil, unsupported("method response models")
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	row, err := tx.Method(key)
	if err != nil {
		return nil, err
	}
	response := MethodResponse{Headers: map[string]bool{}}
	for name, required := range in.ResponseParameters {
		header := strings.TrimPrefix(string(name), "method.response.header.")
		if header == string(name) || header == "" || strings.ContainsAny(header, " \t\r\n:") {
			return nil, bad("Invalid method response header")
		}
		response.Headers[header] = bool(required)
	}
	if row.Responses == nil {
		row.Responses = map[string]MethodResponse{}
	}
	row.Responses[string(value(in.StatusCode))] = response
	if err := tx.PutMethod(row); err != nil {
		return nil, err
	}
	return &api.MethodResponse{StatusCode: in.StatusCode, ResponseParameters: in.ResponseParameters}, nil
}
func (s *Service) putIntegrationResponse(tx Transaction, in *api.PutIntegrationResponseRequest) (*api.IntegrationResponse, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PUT", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/integration/responses/"+string(value(in.StatusCode)))
	if err != nil {
		return nil, err
	}
	status, err := responseStatus(string(value(in.StatusCode)))
	if err != nil {
		return nil, err
	}
	if value(in.SelectionPattern) != "" || in.ContentHandling != nil {
		return nil, unsupported("integration response selection or content handling")
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	row, err := tx.Integration(key)
	if err != nil {
		return nil, err
	}
	if row.Mock == nil {
		return nil, unsupported("responses on AWS_PROXY integrations")
	}
	if row.Mock.StatusCode != status {
		return nil, unsupported("MOCK request and response status must match")
	}
	headers, err := literalHeaders(mapIn(in.ResponseParameters), "method.response.header.")
	if err != nil {
		return nil, err
	}
	body := ""
	for media, template := range in.ResponseTemplates {
		if media != "application/json" || strings.ContainsAny(string(template), "$#") {
			return nil, unsupported("only literal application/json MOCK response templates are supported")
		}
		body = string(template)
	}
	row.Mock.Headers, row.Mock.Body = headers, body
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return &api.IntegrationResponse{StatusCode: in.StatusCode, ResponseParameters: in.ResponseParameters, ResponseTemplates: in.ResponseTemplates}, nil
}
