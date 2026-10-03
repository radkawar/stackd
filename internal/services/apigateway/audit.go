package apigateway

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// REST management events expose HAL relations as parameter objects, not URLs.
// These relations describe the native control-plane representation; they do not
// imply that every linked operation is implemented locally.
type auditLink struct {
	RestAPIID        string   `json:"restApiId,omitempty"`
	ResourceID       string   `json:"resourceId,omitempty"`
	ParentID         string   `json:"parentId,omitempty"`
	HTTPMethod       string   `json:"httpMethod,omitempty"`
	AuthorizerID     string   `json:"authorizerId,omitempty"`
	DeploymentID     string   `json:"deploymentId,omitempty"`
	Template         bool     `json:"template"`
	TemplateSkipList []string `json:"templateSkipList,omitempty"`
	Name             string   `json:"name,omitempty"`
	Title            string   `json:"title,omitempty"`
	Flatten          *bool    `json:"flatten,omitempty"`
	FailOnWarnings   *bool    `json:"failOnWarnings,omitempty"`
}

var auditResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"createdDate": {TimeLayout: time.RFC3339},
}}

var auditUnscopedMethodResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"authorizationScopes": {Mode: awsapi.OmitField},
}}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("apigateway")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get")}
	switch action {
	case "CreateRestApi", "CreateResource", "PutMethod", "PutIntegration", "CreateAuthorizer", "CreateDeployment":
		p.Response = &auditResponse
		if response, ok := out.(*api.Method); ok && response != nil && len(response.AuthorizationScopes) == 0 {
			p.Response = &auditUnscopedMethodResponse
		}
	}
	call, err := p.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventSource = "apigateway.amazonaws.com"
	call.RequestParameters, err = auditRequest(action, call.RequestParameters)
	if err != nil {
		return err
	}
	if rejected == nil && p.Response != nil {
		call.ResponseElements, err = auditResponseLinks(in, out, call.ResponseElements)
		if err != nil {
			return err
		}
	}
	if request, ok := in.(*api.GetRestApiRequest); ok && request != nil && call.ErrorCode == "NotFoundException" {
		call.ErrorMessage = "Invalid API identifier specified " + scopeFor(ctx).AccountID + ":" + value(request.RestApiId)
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

// Only the captured, implemented operations receive native request wrapping.
// TODO: Comeback calibrate other REST operations, account calls, and
// uncaptured validation/authorization errors against native management events.
func auditRequest(action string, body json.RawMessage) (json.RawMessage, error) {
	var wrapper string
	var labels []string
	switch action {
	case "CreateRestApi":
		wrapper = "createRestApiInput"
	case "CreateResource":
		wrapper, labels = "createResourceInput", []string{"restApiId", "parentId"}
	case "PutMethod":
		wrapper, labels = "putMethodInput", []string{"restApiId", "resourceId", "httpMethod"}
	case "PutIntegration":
		wrapper, labels = "putIntegrationInput", []string{"restApiId", "resourceId", "requestHttpMethod"}
	case "CreateAuthorizer":
		wrapper, labels = "createAuthorizerInput", []string{"restApiId"}
	case "CreateDeployment":
		wrapper, labels = "createDeploymentInput", []string{"restApiId"}
	case "GetResources", "GetRestApi", "DeleteRestApi":
	default:
		return body, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		// A binding failure has no generated input to project.
		return body, nil
	}
	if wrapper == "" {
		fields["template"] = json.RawMessage("false")
		return json.Marshal(fields)
	}
	request := make(map[string]json.RawMessage, len(labels)+2)
	for _, name := range labels {
		if field, ok := fields[name]; ok {
			delete(fields, name)
			if name == "requestHttpMethod" {
				name = "httpMethod"
			}
			request[name] = field
		}
	}
	// Native request DTOs materialize these boolean defaults even when omitted
	// by the caller. Explicit values, including values on rejected calls, survive.
	var defaultBoolean string
	switch action {
	case "CreateRestApi":
		defaultBoolean = "disableExecuteApiEndpoint"
	case "PutMethod":
		defaultBoolean = "apiKeyRequired"
	}
	if defaultBoolean != "" && fields[defaultBoolean] == nil {
		fields[defaultBoolean] = json.RawMessage("false")
	}
	input, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	request[wrapper] = input
	request["template"] = json.RawMessage("false")
	return json.Marshal(request)
}

func auditResponseLinks(in, out any, body json.RawMessage) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	var linkError error
	add := func(link auditLink, names ...string) {
		if linkError != nil {
			return
		}
		encoded, err := json.Marshal(link)
		if err != nil {
			linkError = err
			return
		}
		for _, name := range names {
			fields[name] = encoded
		}
	}
	switch request := in.(type) {
	case *api.CreateRestApiRequest:
		response := out.(*api.RestApi)
		link := auditLink{RestAPIID: value(response.Id)}
		add(link, "restapiUpdate", "stageCreate", "restapiAuthorizers", "deploymentCreate", "authorizerCreate", "restapiDelete", "modelCreate", "requestvalidatorCreate", "restapiDocumentationVersions", "documentationpartCreate", "restapiRequestValidators", "documentationversionCreate", "restapiModels", "restapiDocumentationParts", "restapiGatewayResponses", "self")
		link.ParentID = value(response.RootResourceId)
		add(link, "resourceCreate")
		link.ParentID = ""
		link.Template = true
		add(link, "documentationversionByVersion", "documentationpartById", "stageByName", "gatewayresponsePut", "gatewayresponseByType", "requestvalidatorById", "authorizerById", "resourceById")
		link.TemplateSkipList = []string{"position"}
		add(link, "restapiStages", "deploymentById", "restapiResources", "restapiDeployments")
		link.TemplateSkipList = nil
		link.Flatten = new(false)
		add(link, "modelByName")
		link.Flatten = nil
		link.FailOnWarnings = new(false)
		add(link, "documentationpartImport")
	case *api.CreateResourceRequest:
		response := out.(*api.Resource)
		link := auditLink{RestAPIID: value(request.RestApiId), ResourceID: value(response.Id)}
		add(link, "resourceUpdate", "resourceDelete", "self")
		link.Template = true
		add(link, "methodPut", "methodByHttpMethod")
		add(auditLink{RestAPIID: value(request.RestApiId), ParentID: value(response.Id)}, "resourceCreateChild")
	case *api.PutMethodRequest:
		response := out.(*api.Method)
		link := auditLink{RestAPIID: value(request.RestApiId), ResourceID: value(request.ResourceId), HTTPMethod: value(response.HttpMethod)}
		add(link, "methodDelete", "methodUpdate", "integrationPut")
		link.Template = true
		add(link, "methodresponsePut")
		link.Template = false
		link.Name, link.Title = link.HTTPMethod, link.HTTPMethod
		add(link, "self")
	case *api.PutIntegrationRequest:
		link := auditLink{RestAPIID: value(request.RestApiId), ResourceID: value(request.ResourceId), HTTPMethod: value(request.HttpMethod)}
		add(link, "integrationDelete", "integrationUpdate", "self")
		link.Template = true
		add(link, "integrationresponsePut")
	case *api.CreateAuthorizerRequest:
		response := out.(*api.Authorizer)
		link := auditLink{RestAPIID: value(request.RestApiId), AuthorizerID: value(response.Id)}
		add(link, "authorizerUpdate", "authorizerDelete", "self")
	case *api.CreateDeploymentRequest:
		response := out.(*api.Deployment)
		link := auditLink{RestAPIID: value(request.RestApiId), DeploymentID: value(response.Id)}
		add(link, "deploymentUpdate", "deploymentDelete", "self")
		link.TemplateSkipList = []string{"position"}
		add(link, "deploymentStages")
	}
	if linkError != nil {
		return nil, linkError
	}
	return json.Marshal(fields)
}
