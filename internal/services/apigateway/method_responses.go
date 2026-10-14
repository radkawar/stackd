package apigateway

import (
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strconv"
	"strings"
)

func methodResponseOutput(status string, response MethodResponse) *api.MethodResponse {
	parameters := make(api.MapOfStringToBoolean, len(response.Headers))
	for name, required := range response.Headers {
		parameters[api.String("method.response.header."+name)] = api.NullableBoolean(required)
	}
	return &api.MethodResponse{StatusCode: new(api.StatusCode(status)), ResponseParameters: parameters}
}
func parseMethodResponse(parameters api.MapOfStringToBoolean) (MethodResponse, error) {
	response := MethodResponse{Headers: map[string]bool{}}
	for name, required := range parameters {
		header := strings.TrimPrefix(string(name), "method.response.header.")
		if header == string(name) || header == "" || strings.ContainsAny(header, " \t\r\n:") {
			return response, bad("Invalid method response header")
		}
		response.Headers[header] = bool(required)
	}
	return response, nil
}
func (s *Service) responseMethod(tx Transaction, apiID, resource, method, status, verb string) (MethodRecord, error) {
	owner, err := s.api(tx, apiID, verb, methodSuffix(resource, method)+"/responses/"+status)
	if err != nil {
		return MethodRecord{}, err
	}
	if _, err := responseStatus(status); err != nil {
		return MethodRecord{}, err
	}
	return tx.Method(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: resource}, HTTPMethod: method})
}
func (s *Service) putMethodResponse(tx Transaction, in *api.PutMethodResponseRequest) (*api.MethodResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseMethod(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "PUT")
	if err != nil {
		return nil, err
	}
	if len(in.ResponseModels) != 0 {
		return nil, unsupported("method response models")
	}
	response, err := parseMethodResponse(in.ResponseParameters)
	if err != nil {
		return nil, err
	}
	if row.Responses == nil {
		row.Responses = map[string]MethodResponse{}
	}
	row.Responses[status] = response
	if err := tx.PutMethod(row); err != nil {
		return nil, err
	}
	return methodResponseOutput(status, response), nil
}
func (s *Service) getMethodResponse(tx Transaction, in *api.GetMethodResponseRequest) (*api.MethodResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseMethod(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "GET")
	if err != nil {
		return nil, err
	}
	response, ok := row.Responses[status]
	if !ok {
		return nil, ErrNotFound
	}
	return methodResponseOutput(status, response), nil
}
func (s *Service) deleteMethodResponse(tx Transaction, in *api.DeleteMethodResponseRequest) (*api.Unit, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseMethod(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "DELETE")
	if err != nil {
		return nil, err
	}
	if _, ok := row.Responses[status]; !ok {
		return nil, ErrNotFound
	}
	delete(row.Responses, status)
	return &api.Unit{}, tx.PutMethod(row)
}
func (s *Service) updateMethodResponse(tx Transaction, in *api.UpdateMethodResponseRequest) (*api.MethodResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseMethod(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "PATCH")
	if err != nil {
		return nil, err
	}
	response, ok := row.Responses[status]
	if !ok {
		return nil, ErrNotFound
	}
	parameters := map[string]string{}
	for name, required := range response.Headers {
		parameters["method.response.header."+name] = strconv.FormatBool(required)
	}
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		if !strings.HasPrefix(path, "/responseParameters/") {
			return nil, unsupported("method response patch path " + path)
		}
		if err := patchMap(p, "/responseParameters", parameters); err != nil {
			return nil, err
		}
	}
	flags := api.MapOfStringToBoolean{}
	for name, flag := range parameters {
		if flag != "true" && flag != "false" {
			return nil, bad("Method response header flag must be true or false")
		}
		flags[api.String(name)] = api.NullableBoolean(flag == "true")
	}
	response, err = parseMethodResponse(flags)
	if err != nil {
		return nil, err
	}
	row.Responses[status] = response
	if err := tx.PutMethod(row); err != nil {
		return nil, err
	}
	return methodResponseOutput(status, response), nil
}
func integrationResponseOutput(mock *apigatewayexec.MockIntegration) *api.IntegrationResponse {
	parameters := api.MapOfStringToString{}
	for name, value := range mock.Headers {
		parameters[api.String("method.response.header."+name)] = api.String("'" + value + "'")
	}
	out := &api.IntegrationResponse{StatusCode: new(api.StatusCode(strconv.Itoa(mock.StatusCode))), ResponseParameters: parameters, ResponseTemplates: api.MapOfStringToString{}}
	if mock.TemplatePresent || mock.Body != "" {
		out.ResponseTemplates["application/json"] = api.String(mock.Body)
	}
	return out
}
func setIntegrationResponse(mock *apigatewayexec.MockIntegration, parameters, templates map[string]string) error {
	headers, err := literalHeaders(parameters, "method.response.header.")
	if err != nil {
		return err
	}
	for media, template := range templates {
		if media != "application/json" || strings.ContainsAny(template, "$#") {
			return unsupported("only literal application/json MOCK response templates are supported")
		}
	}
	body, present := templates["application/json"]
	mock.Headers, mock.Body, mock.TemplatePresent, mock.ResponseDeleted = headers, body, present, false
	return nil
}
func (s *Service) responseIntegration(tx Transaction, apiID, resource, method, status, verb string) (IntegrationRecord, error) {
	owner, err := s.api(tx, apiID, verb, methodSuffix(resource, method)+"/integration/responses/"+status)
	if err != nil {
		return IntegrationRecord{}, err
	}
	if _, err := responseStatus(status); err != nil {
		return IntegrationRecord{}, err
	}
	row, err := tx.Integration(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: resource}, HTTPMethod: method})
	if err != nil {
		return row, err
	}
	if row.Mock == nil {
		return row, unsupported("responses on AWS_PROXY integrations")
	}
	return row, nil
}
func (s *Service) putIntegrationResponse(tx Transaction, in *api.PutIntegrationResponseRequest) (*api.IntegrationResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseIntegration(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "PUT")
	if err != nil {
		return nil, err
	}
	if value(in.SelectionPattern) != "" || in.ContentHandling != nil {
		// TODO: Comeback execute selection patterns and content conversion through the integration owner.
		return nil, unsupported("integration response selection or content handling")
	}
	if strconv.Itoa(row.Mock.StatusCode) != status {
		return nil, unsupported("MOCK request and response status must match")
	}
	if err := setIntegrationResponse(row.Mock, mapIn(in.ResponseParameters), mapIn(in.ResponseTemplates)); err != nil {
		return nil, err
	}
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return integrationResponseOutput(row.Mock), nil
}
func (s *Service) getIntegrationResponse(tx Transaction, in *api.GetIntegrationResponseRequest) (*api.IntegrationResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseIntegration(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "GET")
	if err != nil {
		return nil, err
	}
	if row.Mock.ResponseDeleted || strconv.Itoa(row.Mock.StatusCode) != status {
		return nil, ErrNotFound
	}
	return integrationResponseOutput(row.Mock), nil
}
func (s *Service) deleteIntegrationResponse(tx Transaction, in *api.DeleteIntegrationResponseRequest) (*api.Unit, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseIntegration(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "DELETE")
	if err != nil {
		return nil, err
	}
	if row.Mock.ResponseDeleted || strconv.Itoa(row.Mock.StatusCode) != status {
		return nil, ErrNotFound
	}
	row.Mock.ResponseDeleted, row.Mock.TemplatePresent, row.Mock.Body, row.Mock.Headers = true, false, "", nil
	return &api.Unit{}, tx.PutIntegration(row)
}
func (s *Service) updateIntegrationResponse(tx Transaction, in *api.UpdateIntegrationResponseRequest) (*api.IntegrationResponse, error) {
	status := string(value(in.StatusCode))
	row, err := s.responseIntegration(tx, value(in.RestApiId), value(in.ResourceId), value(in.HttpMethod), status, "PATCH")
	if err != nil {
		return nil, err
	}
	if row.Mock.ResponseDeleted || strconv.Itoa(row.Mock.StatusCode) != status {
		return nil, ErrNotFound
	}
	out := integrationResponseOutput(row.Mock)
	parameters, templates := mapIn(out.ResponseParameters), mapIn(out.ResponseTemplates)
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		switch {
		case strings.HasPrefix(path, "/responseParameters/"):
			err = patchMap(p, "/responseParameters", parameters)
		case strings.HasPrefix(path, "/responseTemplates/"):
			err = patchMap(p, "/responseTemplates", templates)
		default:
			err = unsupported("integration response patch path " + path)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := setIntegrationResponse(row.Mock, parameters, templates); err != nil {
		return nil, err
	}
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return integrationResponseOutput(row.Mock), nil
}
