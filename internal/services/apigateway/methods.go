package apigateway

import (
	"encoding/json"
	"errors"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
	"strconv"
	"strings"
)

func methodSuffix(resource, method string) string {
	return "/resources/" + resource + "/methods/" + method
}
func methodVerb(v string) bool {
	switch v {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY":
		return true
	}
	return false
}
func methodOutput(r Reader, v MethodRecord) (*api.Method, error) {
	out := &api.Method{HttpMethod: ptr(v.Key.HTTPMethod), AuthorizationType: ptr(v.AuthorizationType), AuthorizerId: optional(v.AuthorizerID), OperationName: optional(v.OperationName), AuthorizationScopes: stringsOut(v.Scopes), ApiKeyRequired: new(api.NullableBoolean(v.APIKeyRequired))}
	if len(v.Responses) != 0 {
		out.MethodResponses = make(api.MapOfMethodResponse, len(v.Responses))
		for status, response := range v.Responses {
			parameters := make(api.MapOfStringToBoolean, len(response.Headers))
			for name, required := range response.Headers {
				parameters[api.String("method.response.header."+name)] = api.NullableBoolean(required)
			}
			out.MethodResponses[api.String(status)] = api.MethodResponse{StatusCode: new(api.StatusCode(status)), ResponseParameters: parameters}
		}
	}
	i, err := r.Integration(v.Key)
	if err == nil {
		out.MethodIntegration = integrationOutput(i)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return out, nil
}
func validateMethod(r Reader, row MethodRecord) error {
	if !methodVerb(row.Key.HTTPMethod) {
		return bad("Invalid HTTP method")
	}
	switch row.AuthorizationType {
	case "NONE", "AWS_IAM":
	case "COGNITO_USER_POOLS", "CUSTOM":
		if row.AuthorizerID == "" {
			return bad("Authorizer id is required")
		}
		a, err := r.Authorizer(AuthorizerKey{APIKey: row.Key.APIKey, AuthorizerID: row.AuthorizerID})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return bad("Invalid authorizer id")
			}
			return err
		}
		if (row.AuthorizationType == "CUSTOM") != (a.LambdaAuthorizer != nil) {
			return bad("Authorizer type does not match method authorization type")
		}
		if row.AuthorizationType == "CUSTOM" && len(row.Scopes) != 0 {
			return unsupported("authorization scopes for Lambda authorizers")
		}
	default:
		return unsupported("authorization type " + row.AuthorizationType)
	}
	for _, v := range row.Scopes {
		if v == "" || strings.ContainsAny(v, " \t\n") {
			return bad("Invalid authorization scope")
		}
	}
	if row.AuthorizationType != "AWS_IAM" {
		integration, err := r.Integration(row.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && integration.CredentialsARN == apigatewayexec.CallerCredentialsARN {
			return bad("AWS_IAM authorization is required for identity forwarding")
		}
	}
	return nil
}
func (s *Service) putMethod(tx Transaction, in *api.PutMethodRequest) (*api.Method, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PUT", methodSuffix(value(in.ResourceId), value(in.HttpMethod)))
	if err != nil {
		return nil, err
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	if _, err := tx.Resource(key.ResourceKey); err != nil {
		return nil, err
	}
	if _, err := tx.Method(key); err == nil {
		return nil, conflict("Method already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// TODO: Comeback request validators/models and declared required request
	// parameters must be enforced by their execution owner before admission.
	if len(in.RequestModels) > 0 || len(in.RequestParameters) > 0 || value(in.RequestValidatorId) != "" {
		return nil, unsupported("request models, request parameters or validators")
	}
	row := MethodRecord{Key: key, AuthorizationType: value(in.AuthorizationType), AuthorizerID: value(in.AuthorizerId), OperationName: value(in.OperationName), Scopes: stringsIn(in.AuthorizationScopes)}
	row.APIKeyRequired = truth(in.ApiKeyRequired)
	if err := validateMethod(tx, row); err != nil {
		return nil, err
	}
	if err := tx.PutMethod(row); err != nil {
		return nil, err
	}
	return methodOutput(tx, row)
}
func (s *Service) getMethod(tx Transaction, in *api.GetMethodRequest) (*api.Method, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", methodSuffix(value(in.ResourceId), value(in.HttpMethod)))
	if err != nil {
		return nil, err
	}
	row, err := tx.Method(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)})
	if err != nil {
		return nil, err
	}
	return methodOutput(tx, row)
}
func (s *Service) deleteMethod(tx Transaction, in *api.DeleteMethodRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", methodSuffix(value(in.ResourceId), value(in.HttpMethod)))
	if err != nil {
		return nil, err
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	if _, err := tx.Method(key); err != nil {
		return nil, err
	}
	return &api.Unit{}, tx.DeleteMethod(key)
}
func (s *Service) updateMethod(tx Transaction, in *api.UpdateMethodRequest) (*api.Method, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", methodSuffix(value(in.ResourceId), value(in.HttpMethod)))
	if err != nil {
		return nil, err
	}
	row, err := tx.Method(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)})
	if err != nil {
		return nil, err
	}
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		switch {
		case path == "/authorizationType":
			err = replace(p, &row.AuthorizationType)
		case path == "/authorizerId":
			err = replace(p, &row.AuthorizerID)
		case path == "/operationName":
			err = replace(p, &row.OperationName)
		case path == "/apiKeyRequired":
			err = patchBool(p, &row.APIKeyRequired)
		case path == "/authorizationScopes" || strings.HasPrefix(path, "/authorizationScopes/"):
			err = patchList(p, "/authorizationScopes", &row.Scopes)
		default:
			err = unsupported("method patch path " + path)
		}
		if err != nil {
			return nil, err
		}
	}
	// Switching to NONE or AWS_IAM leaves the retained authorizer metadata
	// inactive; deployment execution selects only the current authorization type.
	if err := validateMethod(tx, row); err != nil {
		return nil, err
	}
	if err := tx.PutMethod(row); err != nil {
		return nil, err
	}
	return methodOutput(tx, row)
}
func integrationOutput(v IntegrationRecord) *api.Integration {
	if v.Mock != nil {
		status := strconv.Itoa(v.Mock.StatusCode)
		parameters := make(api.MapOfStringToString, len(v.Mock.Headers))
		for name, value := range v.Mock.Headers {
			parameters[api.String("method.response.header."+name)] = api.String("'" + value + "'")
		}
		response := api.IntegrationResponse{StatusCode: new(api.StatusCode(status)), ResponseParameters: parameters}
		if v.Mock.Body != "" {
			response.ResponseTemplates = api.MapOfStringToString{"application/json": api.String(v.Mock.Body)}
		}
		return &api.Integration{Type: new(api.IntegrationTypeMOCK), RequestTemplates: api.MapOfStringToString{"application/json": api.String("{\"statusCode\":" + status + "}")}, IntegrationResponses: api.MapOfIntegrationResponse{api.String(status): response}, PassthroughBehavior: ptr("WHEN_NO_MATCH"), TimeoutInMillis: new(api.Integer(v.TimeoutMillis))}
	}
	return &api.Integration{Type: new(api.IntegrationTypeAWS_PROXY), HttpMethod: ptr("POST"), Uri: ptr(v.URI), Credentials: optional(v.CredentialsARN), PassthroughBehavior: ptr("WHEN_NO_MATCH"), TimeoutInMillis: new(api.Integer(v.TimeoutMillis)), CacheNamespace: ptr(v.Key.ResourceID), CacheKeyParameters: api.ListOfString{}, ResponseTransferMode: new(api.ResponseTransferModeBUFFERED)}
}
func functionARN(uri string, scope Scope) (string, error) {
	prefix := "arn:" + scope.Partition + ":apigateway:" + scope.Region + ":lambda:path/2015-03-31/functions/"
	if !strings.HasPrefix(uri, prefix) || !strings.HasSuffix(uri, "/invocations") {
		return "", bad("Invalid Lambda integration URI")
	}
	arn := strings.TrimSuffix(strings.TrimPrefix(uri, prefix), "/invocations")
	parts := strings.Split(arn, ":")
	if len(parts) < 7 || len(parts) > 8 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "lambda" || parts[3] == "" || len(parts[4]) != 12 || parts[5] != "function" || parts[6] == "" || strings.ContainsAny(arn, "/{}$") {
		return "", bad("Invalid Lambda function ARN")
	}
	for _, c := range parts[4] {
		if c < '0' || c > '9' {
			return "", bad("Invalid Lambda account")
		}
	}
	if len(parts) == 8 && parts[7] == "" {
		return "", bad("Invalid Lambda qualifier")
	}
	return arn, nil
}
func (s *Service) passIntegrationCredentials(tx Transaction, method MethodRecord, credentials string) error {
	if credentials == apigatewayexec.CallerCredentialsARN {
		if method.AuthorizationType != "AWS_IAM" {
			return bad("AWS_IAM authorization is required for identity forwarding")
		}
		return nil
	}
	return s.passCredentials(tx, credentials)
}
func (s *Service) putIntegration(tx Transaction, in *api.PutIntegrationRequest) (*api.Integration, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PUT", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/integration")
	if err != nil {
		return nil, err
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	method, err := tx.Method(key)
	if err != nil {
		return nil, err
	}
	if value(in.Type) == "MOCK" {
		if value(in.CacheNamespace) != "" {
			return nil, unsupported("MOCK cache namespace")
		}
		if value(in.Uri) != "" || value(in.Credentials) != "" || value(in.IntegrationHttpMethod) != "" || len(in.RequestParameters) != 0 || len(in.CacheKeyParameters) != 0 || value(in.ContentHandling) != "" || value(in.ConnectionId) != "" || value(in.IntegrationTarget) != "" || in.TlsConfig != nil {
			return nil, unsupported("MOCK mapping, credentials, URI or connection settings")
		}
		if len(in.RequestTemplates) != 1 {
			return nil, unsupported("MOCK requires one application/json literal status template")
		}
		template, exists := in.RequestTemplates["application/json"]
		var fields map[string]json.RawMessage
		if !exists || json.Unmarshal([]byte(template), &fields) != nil || len(fields) != 1 {
			return nil, unsupported("MOCK requires a static JSON statusCode template; VTL is unsupported")
		}
		var status int
		if json.Unmarshal(fields["statusCode"], &status) != nil || status < 100 || status > 599 {
			return nil, bad("Invalid MOCK request statusCode")
		}
		if v := value(in.PassthroughBehavior); v != "" && v != "WHEN_NO_MATCH" {
			return nil, unsupported("MOCK passthrough behavior")
		}
		if v := value(in.ConnectionType); v != "" && v != "INTERNET" {
			return nil, unsupported("MOCK private connection")
		}
		if v := value(in.ResponseTransferMode); v != "" && v != "BUFFERED" {
			return nil, unsupported("MOCK streaming response")
		}
		if in.TimeoutInMillis != nil && *in.TimeoutInMillis != 29000 {
			return nil, unsupported("nondefault MOCK timeout")
		}
		row := IntegrationRecord{Key: key, TimeoutMillis: 29000, Mock: &apigatewayexec.MockIntegration{StatusCode: status}}
		if err := tx.PutIntegration(row); err != nil {
			return nil, err
		}
		return integrationOutput(row), nil
	}
	// TODO: Comeback nonproxy mappings, private integrations,
	// streaming, configurable timeouts, stage URI substitutions and integration caches.
	if value(in.Type) != "AWS_PROXY" || value(in.IntegrationHttpMethod) != "POST" {
		return nil, unsupported("only POST Lambda AWS_PROXY integrations are supported")
	}
	if len(in.CacheKeyParameters) > 0 || len(in.RequestParameters) > 0 || len(in.RequestTemplates) > 0 || value(in.ContentHandling) != "" || value(in.ConnectionId) != "" || value(in.IntegrationTarget) != "" || in.TlsConfig != nil {
		return nil, unsupported("mapping, caching, private integration or TLS settings")
	}
	if v := value(in.ConnectionType); v != "" && v != "INTERNET" {
		return nil, unsupported("private integration")
	}
	if v := value(in.PassthroughBehavior); v != "" && v != "WHEN_NO_MATCH" {
		return nil, unsupported("passthrough behavior")
	}
	if v := value(in.ResponseTransferMode); v != "" && v != "BUFFERED" {
		return nil, unsupported("streaming integration")
	}
	if in.TimeoutInMillis != nil && *in.TimeoutInMillis != 29000 {
		return nil, unsupported("nondefault integration timeout")
	}
	if v := value(in.CacheNamespace); v != "" && v != key.ResourceID {
		return nil, unsupported("custom cache namespace")
	}
	if _, err := functionARN(value(in.Uri), owner.Key.Scope); err != nil {
		return nil, err
	}
	row := IntegrationRecord{Key: key, URI: value(in.Uri), CredentialsARN: value(in.Credentials), TimeoutMillis: 29000}
	if err := s.passIntegrationCredentials(tx, method, row.CredentialsARN); err != nil {
		return nil, err
	}
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return integrationOutput(row), nil
}
func (s *Service) getIntegration(tx Transaction, in *api.GetIntegrationRequest) (*api.Integration, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/integration")
	if err != nil {
		return nil, err
	}
	row, err := tx.Integration(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)})
	if err != nil {
		return nil, err
	}
	return integrationOutput(row), nil
}
func (s *Service) deleteIntegration(tx Transaction, in *api.DeleteIntegrationRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/integration")
	if err != nil {
		return nil, err
	}
	key := MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)}
	if _, err := tx.Integration(key); err != nil {
		return nil, err
	}
	return &api.Unit{}, tx.DeleteIntegration(key)
}
func (s *Service) updateIntegration(tx Transaction, in *api.UpdateIntegrationRequest) (*api.Integration, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", methodSuffix(value(in.ResourceId), value(in.HttpMethod))+"/integration")
	if err != nil {
		return nil, err
	}
	row, err := tx.Integration(MethodKey{ResourceKey: ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)}, HTTPMethod: value(in.HttpMethod)})
	if err != nil {
		return nil, err
	}
	for _, p := range in.PatchOperations {
		if row.Mock != nil && (value(p.Path) == "/uri" || value(p.Path) == "/credentials" || value(p.Path) == "/httpMethod") {
			return nil, unsupported("MOCK URI, credentials or HTTP method patch")
		}
		switch value(p.Path) {
		case "/uri":
			err = replace(p, &row.URI)
		case "/credentials":
			err = replace(p, &row.CredentialsARN)
			if err == nil {
				var method MethodRecord
				method, err = tx.Method(row.Key)
				if err == nil {
					err = s.passIntegrationCredentials(tx, method, row.CredentialsARN)
				}
			}
		case "/httpMethod":
			v := "POST"
			err = replace(p, &v)
			if err == nil && v != "POST" {
				err = bad("Lambda integrations require POST")
			}
		case "/timeoutInMillis":
			v := "29000"
			err = replace(p, &v)
			if err == nil && v != "29000" {
				err = unsupported("nondefault integration timeout")
			}
		case "/passthroughBehavior":
			v := "WHEN_NO_MATCH"
			err = replace(p, &v)
			if err == nil && v != "WHEN_NO_MATCH" {
				err = unsupported("passthrough behavior")
			}
		case "/responseTransferMode":
			v := "BUFFERED"
			err = replace(p, &v)
			if err == nil && v != "BUFFERED" {
				err = unsupported("streaming integration")
			}
		default:
			err = unsupported("integration patch path " + value(p.Path))
		}
		if err != nil {
			return nil, err
		}
	}
	if row.Mock == nil {
		if _, err := functionARN(row.URI, owner.Key.Scope); err != nil {
			return nil, err
		}
	} else if row.URI != "" || row.CredentialsARN != "" {
		return nil, unsupported("MOCK URI or credentials")
	}
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return integrationOutput(row), nil
}
