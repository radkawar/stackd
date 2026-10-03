package apigatewayexec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stackd/iam/policy"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Authorizer failures retain the distinction needed by each Gateway protocol's
// error response; customer function output is never exposed as a diagnosis.
var (
	ErrAuthorizerInvocation   = errors.New("authorizer invocation failed")
	ErrAuthorizerResponse     = errors.New("invalid authorizer response")
	ErrAuthorizerUnauthorized = errors.New("authorizer rejected the request as unauthorized")
)

// AuthorizerExecutor invokes Lambda authorizers and validates their responses.
// Callers own request identity, payload construction, caching, and policy decisions.
type AuthorizerExecutor struct {
	functions Functions
	roles     InvocationRoles
}

func NewAuthorizerExecutor(functions Functions, roles InvocationRoles) *AuthorizerExecutor {
	return &AuthorizerExecutor{functions: functions, roles: roles}
}

// Invoke executes the route's configured authorizer. A successful policy response
// includes its parsed document so callers need not parse it again on cache misses.
func (s *AuthorizerExecutor) Invoke(ctx context.Context, route *Route, payload []byte, rest bool) (AuthorizerResult, *policy.Document, int64, error) {
	invalid := ErrAuthorizerInvocation
	if s.functions == nil {
		return AuthorizerResult{}, nil, 0, invalid
	}
	config := route.LambdaAuthorizer
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	started := time.Now()
	if config.CredentialsARN != "" {
		if s.roles == nil {
			return AuthorizerResult{}, nil, 0, invalid
		}
		var rejected *awswire.Error
		ctx, rejected = s.roles.InvocationContext(ctx, config.CredentialsARN, rest)
		if rejected != nil {
			return AuthorizerResult{}, nil, 0, invalid
		}
	} else {
		metadata := awsctx.FromContext(ctx)
		metadata.ServicePrincipal = awsctx.ServicePrincipal{Name: "apigateway.amazonaws.com", SourceARN: "arn:" + route.Partition + ":execute-api:" + route.Region + ":" + route.AccountID + ":" + route.APIID + "/authorizers/" + config.ID, Type: "Service"}
		metadata.InvokedBy = "apigateway.amazonaws.com"
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	name := lambdaapi.NamespacedFunctionName(config.FunctionARN)
	output, _, failure := s.functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: &name, Payload: lambdaapi.Blob(payload)})
	latency := time.Since(started).Milliseconds()
	if failure != nil || output == nil {
		return AuthorizerResult{}, nil, latency, invalid
	}
	var response struct {
		PrincipalID        json.RawMessage            `json:"principalId"`
		PolicyDocument     json.RawMessage            `json:"policyDocument"`
		Context            map[string]json.RawMessage `json:"context"`
		IsAuthorized       json.RawMessage            `json:"isAuthorized"`
		ErrorMessage       string                     `json:"errorMessage"`
		UsageIdentifierKey json.RawMessage            `json:"usageIdentifierKey"`
	}
	invalid = ErrAuthorizerResponse
	if json.Unmarshal(output.Payload, &response) != nil {
		return AuthorizerResult{}, nil, latency, invalid
	}
	if response.ErrorMessage == "Unauthorized" {
		return AuthorizerResult{}, nil, latency, ErrAuthorizerUnauthorized
	}
	if output.FunctionError != nil {
		return AuthorizerResult{}, nil, latency, ErrAuthorizerInvocation
	}
	websocket := !rest && config.PayloadVersion == ""
	var principal *string
	if len(response.PrincipalID) != 0 {
		if err := json.Unmarshal(response.PrincipalID, &principal); err != nil {
			var number json.Number
			if !websocket || json.Unmarshal(response.PrincipalID, &number) != nil {
				return AuthorizerResult{}, nil, latency, invalid
			}
			principal = new(number.String())
		}
	}
	result := AuthorizerResult{PrincipalID: principal, PolicyDocument: response.PolicyDocument, Context: response.Context}
	if rest && len(response.UsageIdentifierKey) != 0 {
		if json.Unmarshal(response.UsageIdentifierKey, &result.UsageIdentifierKey) != nil {
			return AuthorizerResult{}, nil, latency, invalid
		}
	}
	var document *policy.Document
	if config.SimpleResponses {
		if len(response.PolicyDocument) != 0 || len(response.IsAuthorized) == 0 {
			return AuthorizerResult{}, nil, latency, invalid
		}
		var allowed bool
		if strings.TrimSpace(string(response.IsAuthorized)) == "null" {
			return AuthorizerResult{}, nil, latency, invalid
		}
		if err := json.Unmarshal(response.IsAuthorized, &allowed); err != nil {
			var value string
			if json.Unmarshal(response.IsAuthorized, &value) != nil || value != "true" && value != "false" {
				return AuthorizerResult{}, nil, latency, invalid
			}
			allowed = value == "true"
		}
		result.IsAuthorized = &allowed
	} else {
		if (!websocket && (principal == nil || *principal == "")) || len(response.IsAuthorized) != 0 {
			return AuthorizerResult{}, nil, latency, invalid
		}
		var err error
		document, err = policy.Parse(response.PolicyDocument)
		if err != nil {
			return AuthorizerResult{}, nil, latency, invalid
		}
	}
	if rest || config.PayloadVersion != "2.0" {
		for name, value := range result.Context {
			var scalar any
			if json.Unmarshal(value, &scalar) != nil {
				return AuthorizerResult{}, nil, latency, invalid
			}
			switch scalar.(type) {
			case string, bool, float64:
			case nil:
				if !websocket {
					return AuthorizerResult{}, nil, latency, invalid
				}
				delete(result.Context, name)
			default:
				return AuthorizerResult{}, nil, latency, invalid
			}
		}
	}
	return result, document, latency, nil
}

// EvaluateAuthorizerPolicy applies the shared execute-api request context.
func EvaluateAuthorizerPolicy(document *policy.Document, resource string, request *http.Request, now time.Time) (policy.Decision, error) {
	sourceIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		sourceIP = request.RemoteAddr
	}
	return policy.Evaluate([]*policy.Document{document}, policy.Request{Action: "execute-api:Invoke", Resource: resource, Context: map[string][]string{"aws:SourceIp": {sourceIP}, "aws:SecureTransport": {strconv.FormatBool(request.TLS != nil)}, "aws:CurrentTime": {now.UTC().Format(time.RFC3339)}}})
}
