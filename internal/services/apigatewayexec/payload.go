package apigatewayexec

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsctx"
)

type jwtContext struct {
	Claims map[string]string `json:"claims"`
	Scopes []string          `json:"scopes"`
}
type iamContext struct {
	AccessKey       string  `json:"accessKey"`
	AccountID       string  `json:"accountId"`
	CallerID        string  `json:"callerId"`
	CognitoIdentity *string `json:"cognitoIdentity"`
	PrincipalOrgID  *string `json:"principalOrgId"`
	UserARN         string  `json:"userArn"`
	UserID          string  `json:"userId"`
}
type authorizerContext struct {
	JWT    *jwtContext       `json:"jwt,omitempty"`
	IAM    *iamContext       `json:"iam,omitempty"`
	Claims map[string]string `json:"claims,omitempty"`
}
type httpContext struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Protocol  string `json:"protocol"`
	SourceIP  string `json:"sourceIp"`
	UserAgent string `json:"userAgent"`
}
type proxyIdentity struct {
	CognitoIdentityPoolID         *string   `json:"cognitoIdentityPoolId"`
	AccountID                     *string   `json:"accountId"`
	CognitoIdentityID             *string   `json:"cognitoIdentityId"`
	Caller                        *string   `json:"caller"`
	SourceIP                      string    `json:"sourceIp"`
	PrincipalOrgID                *string   `json:"principalOrgId"`
	AccessKey                     *string   `json:"accessKey"`
	CognitoAuthenticationType     *string   `json:"cognitoAuthenticationType"`
	CognitoAuthenticationProvider *string   `json:"cognitoAuthenticationProvider"`
	UserARN                       *string   `json:"userArn"`
	UserAgent                     string    `json:"userAgent"`
	User                          *string   `json:"user"`
	CognitoAMR                    *[]string `json:"cognitoAmr,omitempty"`
	APIKey                        string    `json:"apiKey,omitempty"`
	APIKeyID                      string    `json:"apiKeyId,omitempty"`
}
type requestContext struct {
	AccountID         string         `json:"accountId"`
	APIID             string         `json:"apiId"`
	Authorizer        any            `json:"authorizer,omitempty"`
	DomainName        string         `json:"domainName"`
	DomainPrefix      string         `json:"domainPrefix"`
	HTTP              *httpContext   `json:"http,omitempty"`
	RequestID         string         `json:"requestId"`
	RouteKey          string         `json:"routeKey,omitempty"`
	Stage             string         `json:"stage"`
	Time              string         `json:"time,omitempty"`
	TimeEpoch         int64          `json:"timeEpoch,omitempty"`
	ResourceID        string         `json:"resourceId,omitempty"`
	ResourcePath      string         `json:"resourcePath,omitempty"`
	HTTPMethod        string         `json:"httpMethod,omitempty"`
	ExtendedRequestID string         `json:"extendedRequestId,omitempty"`
	RequestTime       string         `json:"requestTime,omitempty"`
	Path              string         `json:"path,omitempty"`
	Protocol          string         `json:"protocol,omitempty"`
	RequestTimeEpoch  int64          `json:"requestTimeEpoch,omitempty"`
	Identity          *proxyIdentity `json:"identity,omitempty"`
	DeploymentID      string         `json:"deploymentId,omitempty"`
}
type payloadV2 struct {
	Version               string            `json:"version"`
	RouteKey              string            `json:"routeKey"`
	RawPath               string            `json:"rawPath"`
	RawQueryString        string            `json:"rawQueryString"`
	Cookies               []string          `json:"cookies,omitempty"`
	Headers               map[string]string `json:"headers"`
	QueryStringParameters map[string]string `json:"queryStringParameters,omitempty"`
	RequestContext        requestContext    `json:"requestContext"`
	Body                  string            `json:"body,omitempty"`
	PathParameters        map[string]string `json:"pathParameters,omitempty"`
	StageVariables        map[string]string `json:"stageVariables,omitempty"`
	IsBase64Encoded       bool              `json:"isBase64Encoded"`
}
type payloadV1 struct {
	Version                         string              `json:"version,omitempty"`
	Resource                        string              `json:"resource"`
	Path                            string              `json:"path"`
	HTTPMethod                      string              `json:"httpMethod"`
	Headers                         map[string]string   `json:"headers"`
	MultiValueHeaders               map[string][]string `json:"multiValueHeaders"`
	QueryStringParameters           map[string]string   `json:"queryStringParameters"`
	MultiValueQueryStringParameters map[string][]string `json:"multiValueQueryStringParameters"`
	PathParameters                  map[string]string   `json:"pathParameters"`
	StageVariables                  map[string]string   `json:"stageVariables"`
	RequestContext                  requestContext      `json:"requestContext"`
	Body                            *string             `json:"body"`
	IsBase64Encoded                 bool                `json:"isBase64Encoded"`
}

func (s *Handler) payload(r *http.Request, route *Route, path string, body []byte, identity requestIdentity, rest bool) any {
	metadata := awsctx.FromContext(r.Context())
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = r.RemoteAddr
	}
	observation := requestObservationFrom(r)
	now := observation.at.UTC()
	formatted := now.Format("02/Jan/2006:15:04:05 -0700")
	domainPrefix, _, _ := strings.Cut(r.Host, ".")
	context := requestContext{AccountID: route.AccountID, APIID: route.APIID, DomainName: r.Host, DomainPrefix: domainPrefix,
		RequestID: observation.requestID, Stage: route.Stage}
	if len(route.PathParameters) == 0 {
		route.PathParameters = nil
	}
	if len(route.StageVariables) == 0 {
		route.StageVariables = nil
	}
	claims := projectedClaims(identity.Claims, rest)
	if identity.Claims != nil {
		authorizer := &authorizerContext{}
		if rest {
			authorizer.Claims = claims
		} else {
			authorizer.JWT = &jwtContext{Claims: claims, Scopes: identity.Scopes}
		}
		context.Authorizer = authorizer
	}
	if identity.Lambda != nil {
		context.Authorizer = lambdaIntegrationContext(identity.Lambda, route.LambdaAuthorizer, rest, identity.LambdaLatency)
	}
	headers := r.Header.Clone()
	if rest && route.AuthorizationType == "AWS_IAM" {
		headers.Del("Authorization")
	}
	headers.Set("Host", r.Host)
	headers.Set("X-Forwarded-For", sourceIP)
	if r.TLS != nil {
		headers.Set("X-Forwarded-Proto", "https")
		headers.Set("X-Forwarded-Port", "443")
	} else {
		headers.Set("X-Forwarded-Proto", "http")
		headers.Set("X-Forwarded-Port", "80")
	}
	headerValues := make(map[string]string, len(headers))
	query := r.URL.Query()
	var queryValues map[string]string
	if len(query) != 0 {
		queryValues = make(map[string]string, len(query))
	}
	if route.PayloadVersion == "2.0" {
		for name, values := range headers {
			headerValues[strings.ToLower(name)] = strings.Join(values, ",")
		}
		if _, present := headerValues["content-length"]; !present {
			headerValues["content-length"] = strconv.Itoa(len(body))
		}
		for name, values := range query {
			queryValues[name] = strings.Join(values, ",")
		}
		context.HTTP = &httpContext{Method: r.Method, Path: path, Protocol: r.Proto, SourceIP: sourceIP, UserAgent: r.UserAgent()}
		context.RouteKey, context.Time, context.TimeEpoch = route.RouteKey, formatted, now.UnixMilli()
		if route.AuthorizationType == "AWS_IAM" {
			context.Authorizer = &authorizerContext{IAM: &iamContext{AccessKey: metadata.AccessKeyID, AccountID: metadata.AccountID, CallerID: metadata.PrincipalID, UserARN: metadata.PrincipalARN, UserID: metadata.PrincipalID}}
		}
		var cookies []string
		for _, header := range r.Header.Values("Cookie") {
			for _, cookie := range strings.Split(header, ";") {
				if cookie = strings.TrimSpace(cookie); cookie != "" {
					cookies = append(cookies, cookie)
				}
			}
		}
		binary := len(body) != 0 && binaryContent(r.Header.Get("Content-Type"))
		text := string(body)
		if binary {
			text = base64.StdEncoding.EncodeToString(body)
		}
		return payloadV2{Version: "2.0", RouteKey: route.RouteKey, RawPath: path, RawQueryString: r.URL.RawQuery,
			Cookies: cookies, Headers: headerValues, QueryStringParameters: queryValues, RequestContext: context, Body: text,
			PathParameters: route.PathParameters, StageVariables: route.StageVariables, IsBase64Encoded: binary}
	}
	for name, values := range headers {
		if len(values) != 0 {
			headerValues[name] = values[len(values)-1]
		}
	}
	for name, values := range query {
		if len(values) != 0 {
			queryValues[name] = values[len(values)-1]
		}
	}
	if len(query) == 0 {
		query = nil
	}
	context.ResourceID, context.ResourcePath, context.HTTPMethod = route.ResourceID, route.ResourcePath, r.Method
	context.ExtendedRequestID, context.RequestTime, context.RequestTimeEpoch = observation.extendedRequestID, formatted, now.UnixMilli()
	context.Path, context.Protocol, context.DeploymentID = path, r.Proto, route.DeploymentID
	context.Identity = &proxyIdentity{SourceIP: sourceIP, UserAgent: r.UserAgent()}
	if rest {
		context.Identity.APIKey, context.Identity.APIKeyID = identity.APIKey.Value, identity.APIKey.ID
	}
	if route.AuthorizationType == "AWS_IAM" {
		context.Identity.AccountID, context.Identity.Caller, context.Identity.AccessKey = &metadata.AccountID, &metadata.PrincipalID, &metadata.AccessKeyID
		context.Identity.UserARN, context.Identity.User = &metadata.PrincipalARN, &metadata.PrincipalID
	}
	var text *string
	binary := rest && len(body) != 0 && binaryMedia(r.Header.Get("Content-Type"), route.BinaryMediaTypes)
	if len(body) != 0 {
		value := string(body)
		if binary {
			value = base64.StdEncoding.EncodeToString(body)
		}
		text = &value
	}
	version := ""
	if !rest {
		version = "1.0"
	}
	return payloadV1{Version: version, Resource: route.ResourcePath, Path: executionPath(route, path), HTTPMethod: r.Method, Headers: headerValues,
		MultiValueHeaders: headers, QueryStringParameters: queryValues, MultiValueQueryStringParameters: query,
		PathParameters: route.PathParameters, StageVariables: route.StageVariables, RequestContext: context, Body: text, IsBase64Encoded: binary}
}

func binaryContent(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	return contentType != "" && !strings.HasPrefix(contentType, "text/") && contentType != "application/json" && !strings.HasSuffix(contentType, "+json") && contentType != "application/xml" && !strings.HasSuffix(contentType, "+xml") && contentType != "application/x-www-form-urlencoded"
}

func projectedClaims(claims map[string]json.RawMessage, rest bool) map[string]string {
	if claims == nil {
		return nil
	}
	result := make(map[string]string, len(claims))
	for key, raw := range claims {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			value = string(raw)
		}
		if rest && (key == "exp" || key == "iat" || key == "nbf") {
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
				value = time.Unix(seconds, 0).UTC().Format("Mon Jan 02 15:04:05 MST 2006")
			}
		}
		result[key] = value
	}
	return result
}
