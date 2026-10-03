package apigatewayexec

import (
	"net/http"
	"strings"
)

type authorizerRequestV1 struct {
	Version                         string               `json:"version,omitempty"`
	Type                            string               `json:"type"`
	MethodARN                       string               `json:"methodArn"`
	IdentitySource                  *string              `json:"identitySource,omitempty"`
	AuthorizationToken              *string              `json:"authorizationToken,omitempty"`
	Resource                        string               `json:"resource"`
	Path                            string               `json:"path"`
	HTTPMethod                      string               `json:"httpMethod"`
	Headers                         map[string]string    `json:"headers"`
	MultiValueHeaders               *map[string][]string `json:"multiValueHeaders,omitempty"`
	QueryStringParameters           map[string]string    `json:"queryStringParameters"`
	MultiValueQueryStringParameters *map[string][]string `json:"multiValueQueryStringParameters,omitempty"`
	PathParameters                  map[string]string    `json:"pathParameters"`
	StageVariables                  map[string]string    `json:"stageVariables"`
	RequestContext                  requestContext       `json:"requestContext"`
}

type authorizerRequestV2 struct {
	Version               string            `json:"version"`
	Type                  string            `json:"type"`
	RouteARN              string            `json:"routeArn"`
	IdentitySource        []string          `json:"identitySource"`
	RouteKey              string            `json:"routeKey"`
	RawPath               string            `json:"rawPath"`
	RawQueryString        string            `json:"rawQueryString"`
	Cookies               []string          `json:"cookies,omitempty"`
	Headers               map[string]string `json:"headers"`
	QueryStringParameters map[string]string `json:"queryStringParameters,omitempty"`
	PathParameters        map[string]string `json:"pathParameters,omitempty"`
	StageVariables        map[string]string `json:"stageVariables,omitempty"`
	RequestContext        requestContext    `json:"requestContext"`
}

func (s *Handler) authorizerPayload(r *http.Request, route *Route, path string, identities []string, rest bool) any {
	config := route.LambdaAuthorizer
	resource := executionARN(route, r.Method, executionPath(route, path))
	if config.Type == "TOKEN" {
		return struct {
			Type      string `json:"type"`
			MethodARN string `json:"methodArn"`
			Token     string `json:"authorizationToken"`
		}{"TOKEN", resource, identities[0]}
	}
	projected := *route
	projected.PayloadVersion = config.PayloadVersion
	if rest {
		projected.PayloadVersion = "1.0"
	}
	switch value := s.payload(r, &projected, path, nil, requestIdentity{}, rest).(type) {
	case payloadV2:
		return authorizerRequestV2{Version: "2.0", Type: "REQUEST", RouteARN: resource, IdentitySource: identities,
			RouteKey: value.RouteKey, RawPath: value.RawPath, RawQueryString: value.RawQueryString, Cookies: value.Cookies,
			Headers: value.Headers, QueryStringParameters: value.QueryStringParameters, PathParameters: value.PathParameters,
			StageVariables: value.StageVariables, RequestContext: value.RequestContext}
	case payloadV1:
		if value.QueryStringParameters == nil {
			value.QueryStringParameters = map[string]string{}
		}
		if value.PathParameters == nil {
			value.PathParameters = map[string]string{}
		}
		if value.StageVariables == nil {
			value.StageVariables = map[string]string{}
		}
		result := authorizerRequestV1{Version: value.Version, Type: "REQUEST", MethodARN: resource,
			Resource: value.Resource, Path: value.Path, HTTPMethod: value.HTTPMethod, Headers: value.Headers,
			QueryStringParameters: value.QueryStringParameters, PathParameters: value.PathParameters,
			StageVariables: value.StageVariables, RequestContext: value.RequestContext}
		if rest {
			if value.MultiValueQueryStringParameters == nil {
				value.MultiValueQueryStringParameters = map[string][]string{}
			}
			result.MultiValueHeaders = &value.MultiValueHeaders
			result.MultiValueQueryStringParameters = &value.MultiValueQueryStringParameters
		} else {
			identity := strings.Join(identities, ",")
			result.IdentitySource, result.AuthorizationToken = &identity, &identity
			result.Resource = ""
			result.RequestContext.ResourceID = route.RouteKey
			result.RequestContext.ExtendedRequestID = result.RequestContext.RequestID
			result.RequestContext.DeploymentID = ""
			var amr []string
			result.RequestContext.Identity.CognitoAMR = &amr
			if _, ok := result.Headers["Content-Length"]; !ok {
				result.Headers["Content-Length"] = "0"
			}
		}
		return result
	default:
		panic("unreachable proxy payload type")
	}
}
