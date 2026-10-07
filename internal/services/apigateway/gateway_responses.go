package apigateway

import (
	"mime"
	"slices"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strconv"
	"strings"
)

func validateBinaryMediaTypes(types []string) error {
	for _, media := range types {
		parsed, parameters, err := mime.ParseMediaType(media)
		if err != nil || len(parameters) != 0 || parsed != media || !strings.Contains(media, "/") {
			return bad("Invalid binary media type: " + media)
		}
	}
	return nil
}
func literalHeaders(parameters map[string]string, prefix string) (map[string]string, error) {
	headers := map[string]string{}
	for key, v := range parameters {
		name := strings.TrimPrefix(key, prefix)
		if name == key || name == "" || strings.ContainsAny(name, " \t\r\n:") || len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' || strings.ContainsAny(v, "\r\n") {
			return nil, unsupported("only literal response headers are supported: " + key)
		}
		headers[name] = v[1 : len(v)-1]
	}
	return headers, nil
}
func responseStatus(text string) (int, error) {
	status, err := strconv.Atoi(text)
	if err != nil || status < 100 || status > 599 || len(text) != 3 {
		return 0, bad("Invalid response status code")
	}
	return status, nil
}
func parseGatewayResponse(kind, status string, parameters, templates map[string]string) (apigatewayexec.GatewayResponse, error) {
	out := apigatewayexec.GatewayResponse{}
	if kind != "DEFAULT_4XX" && kind != "DEFAULT_5XX" {
		return out, unsupported("gateway response type " + kind)
	}
	var err error
	if status != "" {
		out.StatusCode, err = responseStatus(status)
		if err != nil {
			return out, err
		}
	}
	out.Headers, err = literalHeaders(parameters, "gatewayresponse.header.")
	if err != nil {
		return out, err
	}
	out.Templates = map[string]string{}
	for media, template := range templates {
		if media != "application/json" {
			return out, unsupported("gateway response template media type " + media)
		}
		remaining := template
		for _, key := range []string{"$context.error.messageString", "$context.error.message", "$context.error.responseType"} {
			remaining = strings.ReplaceAll(remaining, key, "")
		}
		if strings.ContainsAny(remaining, "$#") {
			return out, unsupported("gateway response template expression")
		}
		out.Templates[media] = template
	}
	return out, nil
}
func gatewayResponseOutput(kind string, v apigatewayexec.GatewayResponse) *api.GatewayResponse {
	parameters := api.MapOfStringToString{}
	for name, value := range v.Headers {
		parameters[api.String("gatewayresponse.header."+name)] = api.String("'" + value + "'")
	}
	out := &api.GatewayResponse{ResponseType: new(api.GatewayResponseType(kind)), ResponseParameters: parameters, ResponseTemplates: mapOut(v.Templates), DefaultResponse: new(api.Boolean(false))}
	if v.StatusCode != 0 {
		out.StatusCode = new(api.StatusCode(strconv.Itoa(v.StatusCode)))
	}
	return out
}
func (s *Service) putGatewayResponse(tx Transaction, in *api.PutGatewayResponseRequest) (*api.GatewayResponse, error) {
	kind := string(value(in.ResponseType))
	owner, err := s.api(tx, value(in.RestApiId), "PUT", "/gatewayresponses/"+kind)
	if err != nil {
		return nil, err
	}
	response, err := parseGatewayResponse(kind, string(value(in.StatusCode)), mapIn(in.ResponseParameters), mapIn(in.ResponseTemplates))
	if err != nil {
		return nil, err
	}
	if owner.GatewayResponses == nil {
		owner.GatewayResponses = map[string]apigatewayexec.GatewayResponse{}
	}
	owner.GatewayResponses[kind] = response
	if err := tx.PutAPI(owner); err != nil {
		return nil, err
	}
	return gatewayResponseOutput(kind, response), nil
}
func (s *Service) getGatewayResponse(tx Transaction, in *api.GetGatewayResponseRequest) (*api.GatewayResponse, error) {
	kind := string(value(in.ResponseType))
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/gatewayresponses/"+kind)
	if err != nil {
		return nil, err
	}
	response, ok := owner.GatewayResponses[kind]
	if !ok {
		return nil, ErrNotFound
	}
	return gatewayResponseOutput(kind, response), nil
}
func (s *Service) getGatewayResponses(tx Transaction, in *api.GetGatewayResponsesRequest) (*api.GatewayResponses, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/gatewayresponses")
	if err != nil {
		return nil, err
	}
	keys := sortedKeys(owner.GatewayResponses)
	keys, next, err := page(keys, owner.Key.Scope, "gatewayresponses/"+owner.Key.ID, in.Limit, in.Position, func(v string) string { return v })
	if err != nil {
		return nil, err
	}
	out := &api.GatewayResponses{Items: api.ListOfGatewayResponse{}, Position: next}
	for _, kind := range keys {
		out.Items = append(out.Items, *gatewayResponseOutput(kind, owner.GatewayResponses[kind]))
	}
	return out, nil
}
func (s *Service) deleteGatewayResponse(tx Transaction, in *api.DeleteGatewayResponseRequest) (*api.Unit, error) {
	kind := string(value(in.ResponseType))
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/gatewayresponses/"+kind)
	if err != nil {
		return nil, err
	}
	if kind != "DEFAULT_4XX" && kind != "DEFAULT_5XX" {
		return nil, unsupported("gateway response type " + kind)
	}
	delete(owner.GatewayResponses, kind)
	return &api.Unit{}, tx.PutAPI(owner)
}
func patchBinaryMediaTypes(row *APIRecord, p api.PatchOperation) error {
	path := strings.TrimPrefix(value(p.Path), "/binaryMediaTypes/")
	media := strings.ReplaceAll(strings.ReplaceAll(path, "~1", "/"), "~0", "~")
	if err := validateBinaryMediaTypes([]string{media}); err != nil {
		return err
	}
	index := slices.Index(row.BinaryMediaTypes, media)
	switch value(p.Op) {
	case "add":
		if index < 0 {
			row.BinaryMediaTypes = append(row.BinaryMediaTypes, media)
		}
	case "remove":
		if index >= 0 {
			row.BinaryMediaTypes = slices.Delete(row.BinaryMediaTypes, index, index+1)
		}
	case "replace":
		next := value(p.Value)
		if err := validateBinaryMediaTypes([]string{next}); err != nil {
			return err
		}
		if index < 0 {
			return bad("Binary media type does not exist")
		}
		row.BinaryMediaTypes[index] = next
	default:
		return bad("Invalid binary media type patch operation")
	}
	return nil
}
