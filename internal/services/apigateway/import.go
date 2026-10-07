package apigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strings"
)

// ImportConfiguration carries CloudFormation properties through the same native
// import transaction. It is not a second control-plane or execution authority.
type ImportConfiguration struct {
	Create                   *api.CreateRestApiRequest
	Patches                  api.ListOfPatchOperation
	BinaryMediaTypes         []string
	PreserveBinaryMediaTypes bool
}
type importConfigurationKey struct{}

func WithImportConfiguration(ctx context.Context, v ImportConfiguration) context.Context {
	return context.WithValue(ctx, importConfigurationKey{}, v)
}

type swaggerDefinition struct {
	Swagger string `json:"swagger"`
	Info    struct {
		Title       string  `json:"title"`
		Version     string  `json:"version"`
		Description *string `json:"description"`
	} `json:"info"`
	Paths               map[string]map[string]swaggerOperation `json:"paths"`
	SecurityDefinitions map[string]swaggerSecurity             `json:"securityDefinitions"`
	Security            []map[string][]string                  `json:"security"`
	BinaryMediaTypes    []string                               `json:"x-amazon-apigateway-binary-media-types"`
	GatewayResponses    map[string]swaggerGatewayResponse      `json:"x-amazon-apigateway-gateway-responses"`
	Consumes            []string                               `json:"consumes"`
	Produces            []string                               `json:"produces"`
}
type swaggerSecurity struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	In         string `json:"in"`
	AuthType   string `json:"x-amazon-apigateway-authtype"`
	Authorizer struct {
		Type         string   `json:"type"`
		ProviderARNs []string `json:"providerARNs"`
	} `json:"x-amazon-apigateway-authorizer"`
}
type swaggerOperation struct {
	Security    *[]map[string][]string     `json:"security"`
	OperationID string                     `json:"operationId"`
	Consumes    []string                   `json:"consumes"`
	Produces    []string                   `json:"produces"`
	Responses   map[string]swaggerResponse `json:"responses"`
	Integration swaggerIntegration         `json:"x-amazon-apigateway-integration"`
}
type swaggerResponse struct {
	Description string `json:"description"`
	Headers     map[string]struct {
		Type string `json:"type"`
	} `json:"headers"`
}
type swaggerIntegration struct {
	Type                string                                `json:"type"`
	HTTPMethod          string                                `json:"httpMethod"`
	URI                 string                                `json:"uri"`
	Credentials         string                                `json:"credentials"`
	TimeoutMillis       *api.NullableInteger                  `json:"timeoutInMillis"`
	PassthroughBehavior string                                `json:"passthroughBehavior"`
	RequestTemplates    map[string]string                     `json:"requestTemplates"`
	Responses           map[string]swaggerIntegrationResponse `json:"responses"`
}
type swaggerIntegrationResponse struct {
	StatusCode         string            `json:"statusCode"`
	ResponseParameters map[string]string `json:"responseParameters"`
	ResponseTemplates  map[string]string `json:"responseTemplates"`
}
type swaggerGatewayResponse struct {
	StatusCode         string            `json:"statusCode"`
	ResponseParameters map[string]string `json:"responseParameters"`
	ResponseTemplates  map[string]string `json:"responseTemplates"`
}

func parseSwagger(body []byte) (swaggerDefinition, error) {
	var doc swaggerDefinition
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return doc, bad("Unsupported or invalid Swagger definition: " + err.Error())
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return doc, bad("Swagger definition must contain one JSON document")
	}
	// TODO: Comeback implement OpenAPI 3 and general mapping/integration families;
	// Swagger 2.0 Lambda proxy and literal MOCK imports do not cover those surfaces.
	if doc.Swagger != "2.0" {
		return doc, unsupported("only Swagger 2.0 imports are supported")
	}
	if strings.TrimSpace(doc.Info.Title) == "" || len(doc.Info.Title) > 1024 {
		return doc, bad("Swagger info.title must be nonempty and at most 1024 bytes")
	}
	if strings.TrimSpace(doc.Info.Version) == "" {
		return doc, bad("Swagger info.version is required")
	}
	if doc.Paths == nil {
		return doc, bad("Swagger paths is required")
	}
	return doc, nil
}
func validateImportParameters(parameters api.MapOfStringToString) error {
	for key, v := range parameters {
		if key != "endpointConfigurationTypes" || v != "REGIONAL" {
			return unsupported("import parameter " + string(key))
		}
	}
	return nil
}
func (s *Service) importRestAPI(tx Transaction, in *api.ImportRestApiRequest) (*api.RestApi, error) {
	if err := validateImportParameters(in.Parameters); err != nil {
		return nil, err
	}
	doc, err := parseSwagger(in.Body)
	if err != nil {
		return nil, err
	}
	request := &api.CreateRestApiRequest{Name: ptr(doc.Info.Title), Version: optional(doc.Info.Version), EndpointConfiguration: &api.EndpointConfiguration{Types: api.ListOfEndpointType{api.EndpointTypeREGIONAL}}}
	if doc.Info.Description != nil {
		request.Description = ptr(*doc.Info.Description)
	}
	configuration, _ := tx.Context().Value(importConfigurationKey{}).(ImportConfiguration)
	if configuration.Create != nil {
		request = configuration.Create
	}
	if request.Name == nil {
		request.Name = ptr(doc.Info.Title)
	}
	if request.Description == nil && doc.Info.Description != nil {
		request.Description = ptr(*doc.Info.Description)
	}
	if request.Version == nil {
		request.Version = optional(doc.Info.Version)
	}
	result, err := s.createRestAPI(tx, request)
	if err != nil {
		return nil, err
	}
	owner, err := tx.API(APIKey{Scope: scopeFor(tx.Context()), ID: value(result.Id)})
	if err != nil {
		return nil, err
	}
	return s.applySwagger(tx, owner, doc, "merge", configuration)
}
func (s *Service) putRestAPI(tx Transaction, in *api.PutRestApiRequest) (*api.RestApi, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PUT", "")
	if err != nil {
		return nil, err
	}
	if err := validateImportParameters(in.Parameters); err != nil {
		return nil, err
	}
	doc, err := parseSwagger(in.Body)
	if err != nil {
		return nil, err
	}
	mode := string(value(in.Mode))
	if mode == "" {
		mode = "merge"
	}
	if mode != "merge" && mode != "overwrite" {
		return nil, bad("mode must be merge or overwrite")
	}
	configuration, _ := tx.Context().Value(importConfigurationKey{}).(ImportConfiguration)
	result, err := s.applySwagger(tx, owner, doc, mode, configuration)
	if err != nil {
		return nil, err
	}
	if len(configuration.Patches) != 0 {
		return s.updateRestAPI(tx, &api.UpdateRestApiRequest{RestApiId: result.Id, PatchOperations: configuration.Patches})
	}
	return result, nil
}
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
func (s *Service) applySwagger(tx Transaction, owner APIRecord, doc swaggerDefinition, mode string, configuration ImportConfiguration) (*api.RestApi, error) {
	if mode == "overwrite" {
		methods, err := tx.Methods(owner.Key)
		if err != nil {
			return nil, err
		}
		for _, m := range methods {
			if err := tx.DeleteMethod(m.Key); err != nil {
				return nil, err
			}
		}
		resources, err := tx.Resources(owner.Key)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(resources, func(a, b ResourceRecord) int { return len(b.Path) - len(a.Path) })
		for _, r := range resources {
			if r.Key.ResourceID != owner.RootResourceID {
				if err := tx.DeleteResource(r.Key); err != nil {
					return nil, err
				}
			}
		}
		authorizers, err := tx.Authorizers(owner.Key)
		if err != nil {
			return nil, err
		}
		for _, a := range authorizers {
			if err := tx.DeleteAuthorizer(a.Key); err != nil {
				return nil, err
			}
		}
		if !configuration.PreserveBinaryMediaTypes {
			owner.BinaryMediaTypes = nil
		}
		owner.GatewayResponses = nil
		owner.APIKeySource = "HEADER"
		owner.Disabled = false
	}
	owner.Name, owner.Version = doc.Info.Title, doc.Info.Version
	if doc.Info.Description != nil {
		owner.Description = *doc.Info.Description
	} else if mode == "overwrite" {
		owner.Description = ""
	}
	if configuration.Create != nil {
		if configuration.Create.Name != nil {
			owner.Name = value(configuration.Create.Name)
		}
		if configuration.Create.Description != nil {
			owner.Description = value(configuration.Create.Description)
		}
		if configuration.Create.Version != nil {
			owner.Version = value(configuration.Create.Version)
		}
	}
	binary := append(slices.Clone(doc.BinaryMediaTypes), configuration.BinaryMediaTypes...)
	if err := validateBinaryMediaTypes(binary); err != nil {
		return nil, err
	}
	for _, media := range binary {
		if !slices.Contains(owner.BinaryMediaTypes, media) {
			owner.BinaryMediaTypes = append(owner.BinaryMediaTypes, media)
		}
	}
	if owner.GatewayResponses == nil {
		owner.GatewayResponses = map[string]apigatewayexec.GatewayResponse{}
	}
	for _, kind := range sortedKeys(doc.GatewayResponses) {
		v := doc.GatewayResponses[kind]
		response, err := parseGatewayResponse(kind, v.StatusCode, v.ResponseParameters, v.ResponseTemplates)
		if err != nil {
			return nil, err
		}
		owner.GatewayResponses[kind] = response
	}
	if err := tx.PutAPI(owner); err != nil {
		return nil, err
	}
	authorizers, err := tx.Authorizers(owner.Key)
	if err != nil {
		return nil, err
	}
	ids := map[string]string{}
	for _, a := range authorizers {
		ids[a.Name] = a.Key.AuthorizerID
	}
	for _, name := range sortedKeys(doc.SecurityDefinitions) {
		security := doc.SecurityDefinitions[name]
		if security.Type != "apiKey" || security.Name != "Authorization" || security.In != "header" || security.Authorizer.Type != "cognito_user_pools" || (security.AuthType != "" && security.AuthType != "cognito_user_pools") {
			return nil, unsupported("security definition " + name)
		}
		if id := ids[name]; id != "" {
			row, err := tx.Authorizer(AuthorizerKey{APIKey: owner.Key, AuthorizerID: id})
			if err != nil {
				return nil, err
			}
			row.ProviderARNs = slices.Clone(security.Authorizer.ProviderARNs)
			row.LambdaAuthorizer = nil
			row.URI = ""
			row.AuthType = "cognito_user_pools"
			if err := validateAuthorizer(&row); err != nil {
				return nil, err
			}
			if err := tx.PutAuthorizer(row); err != nil {
				return nil, err
			}
			continue
		}
		pools := api.ListOfARNs{}
		for _, arn := range security.Authorizer.ProviderARNs {
			pools = append(pools, api.ProviderARN(arn))
		}
		a, err := s.createAuthorizer(tx, &api.CreateAuthorizerRequest{RestApiId: ptr(owner.Key.ID), Name: ptr(name), Type: new(api.AuthorizerTypeCOGNITO_USER_POOLS), ProviderARNs: pools, IdentitySource: ptr("method.request.header.Authorization")})
		if err != nil {
			return nil, err
		}
		ids[name] = value(a.Id)
	}
	resources, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	paths := map[string]string{}
	for _, r := range resources {
		paths[r.Path] = r.Key.ResourceID
	}
	for _, path := range sortedKeys(doc.Paths) {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || (path != "/" && strings.HasSuffix(path, "/")) {
			return nil, bad("Invalid Swagger path: " + path)
		}
		parent := owner.RootResourceID
		current := ""
		if path != "/" {
			for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
				current += "/" + part
				if paths[current] == "" {
					r, err := s.createResource(tx, &api.CreateResourceRequest{RestApiId: ptr(owner.Key.ID), ParentId: ptr(parent), PathPart: ptr(part)})
					if err != nil {
						return nil, err
					}
					paths[current] = value(r.Id)
				}
				parent = paths[current]
			}
		}
		for _, verb := range sortedKeys(doc.Paths[path]) {
			method := strings.ToUpper(verb)
			if verb == "x-amazon-apigateway-any-method" {
				method = "ANY"
			}
			if !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}, method) {
				return nil, unsupported("Swagger path item " + verb)
			}
			op := doc.Paths[path][verb]
			requirements := doc.Security
			if op.Security != nil {
				requirements = *op.Security
			}
			auth, id := "NONE", ""
			scopes := api.ListOfString{}
			if len(requirements) > 0 {
				if len(requirements) != 1 || len(requirements[0]) != 1 {
					return nil, unsupported("alternative or combined security requirements")
				}
				for name, required := range requirements[0] {
					id = ids[name]
					if id == "" {
						return nil, bad("Unknown security definition " + name)
					}
					auth = "COGNITO_USER_POOLS"
					for _, scope := range required {
						scopes = append(scopes, api.String(scope))
					}
				}
			}
			key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: parent}, HTTPMethod: method}
			if _, err := tx.Method(key); err == nil {
				if err := tx.DeleteMethod(key); err != nil {
					return nil, err
				}
			} else if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if _, err := s.putMethod(tx, &api.PutMethodRequest{RestApiId: ptr(owner.Key.ID), ResourceId: ptr(parent), HttpMethod: ptr(method), AuthorizationType: ptr(auth), AuthorizerId: optional(id), AuthorizationScopes: scopes, OperationName: optional(op.OperationID)}); err != nil {
				return nil, err
			}
			integration := op.Integration
			kind := api.IntegrationType(strings.ToUpper(integration.Type))
			if kind != api.IntegrationTypeAWS_PROXY && kind != api.IntegrationTypeMOCK {
				return nil, unsupported("Swagger integration type " + integration.Type)
			}
			templates := mapOut(integration.RequestTemplates)
			if _, err := s.putIntegration(tx, &api.PutIntegrationRequest{RestApiId: ptr(owner.Key.ID), ResourceId: ptr(parent), HttpMethod: ptr(method), Type: &kind, IntegrationHttpMethod: optional(integration.HTTPMethod), Uri: optional(integration.URI), Credentials: optional(integration.Credentials), TimeoutInMillis: integration.TimeoutMillis, PassthroughBehavior: optional(integration.PassthroughBehavior), RequestTemplates: templates}); err != nil {
				return nil, err
			}
			if kind == api.IntegrationTypeMOCK {
				if len(integration.Responses) != 1 {
					return nil, unsupported("MOCK requires one default integration response")
				}
				response, ok := integration.Responses["default"]
				if !ok {
					return nil, unsupported("MOCK response selection patterns")
				}
				if _, err := s.putIntegrationResponse(tx, &api.PutIntegrationResponseRequest{RestApiId: ptr(owner.Key.ID), ResourceId: ptr(parent), HttpMethod: ptr(method), StatusCode: new(api.StatusCode(response.StatusCode)), ResponseParameters: mapOut(response.ResponseParameters), ResponseTemplates: mapOut(response.ResponseTemplates)}); err != nil {
					return nil, err
				}
			} else if len(integration.Responses) != 0 {
				return nil, unsupported("AWS_PROXY integration responses")
			}
			for status, response := range op.Responses {
				if status == "default" {
					return nil, unsupported("default method response")
				}
				parameters := api.MapOfStringToBoolean{}
				for name, header := range response.Headers {
					if header.Type != "string" {
						return nil, unsupported("non-string response header")
					}
					parameters[api.String("method.response.header."+name)] = false
				}
				if _, err := s.putMethodResponse(tx, &api.PutMethodResponseRequest{RestApiId: ptr(owner.Key.ID), ResourceId: ptr(parent), HttpMethod: ptr(method), StatusCode: new(api.StatusCode(status)), ResponseParameters: parameters}); err != nil {
					return nil, err
				}
			}
		}
	}
	return apiOutput(owner), nil
}
