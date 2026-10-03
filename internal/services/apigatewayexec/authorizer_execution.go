package apigatewayexec

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"stackd/iam/policy"
	"stackd/internal/awsctx"
)

func (s *Handler) authorizeLambda(r *http.Request, route *Route, path string, rest bool) (requestIdentity, *rejection) {
	invalid := &rejection{http.StatusInternalServerError, "Internal Server Error"}
	unauthorized := &rejection{http.StatusUnauthorized, "Unauthorized"}
	config := route.LambdaAuthorizer
	if config == nil {
		return requestIdentity{}, invalid
	}
	identities, present := AuthorizerIdentities(r, route, path, rest, nil)
	if !present {
		return requestIdentity{}, unauthorized
	}
	if config.ValidationExpression != "" {
		compiled, ok := s.validationPatterns.Load(config.ValidationExpression)
		if !ok {
			pattern, err := regexp2.Compile(config.ValidationExpression, 0)
			if err != nil {
				return requestIdentity{}, invalid
			}
			pattern.MatchTimeout = time.Second
			compiled, _ = s.validationPatterns.LoadOrStore(config.ValidationExpression, pattern)
		}
		matches, err := compiled.(*regexp2.Regexp).MatchString(identities[0])
		if err != nil || !matches {
			return requestIdentity{}, unauthorized
		}
	}
	encodedKey, _ := json.Marshal(identities)
	key := string(encodedKey)
	var cache AuthorizerCache = s.http
	if rest {
		cache = s.rest
	}
	var result AuthorizerResult
	hit := false
	if config.TTLSeconds > 0 {
		var err error
		result, hit, err = cache.LoadAuthorizerResult(r.Context(), route, key)
		if err != nil {
			return requestIdentity{}, invalid
		}
	}
	var latency int64
	var document *policy.Document
	if !hit {
		payload, err := json.Marshal(s.authorizerPayload(r, route, path, identities, rest))
		if err != nil {
			return requestIdentity{}, invalid
		}
		var rejected error
		result, document, latency, rejected = s.authorizers.Invoke(r.Context(), route, payload, rest)
		if rejected != nil {
			if errors.Is(rejected, ErrAuthorizerUnauthorized) {
				return requestIdentity{}, unauthorized
			}
			return requestIdentity{}, invalid
		}
		if config.TTLSeconds > 0 {
			if err := cache.StoreAuthorizerResult(r.Context(), route, key, result); err != nil {
				return requestIdentity{}, invalid
			}
		}
	}
	if result.IsAuthorized != nil {
		if !*result.IsAuthorized {
			return requestIdentity{}, &rejection{http.StatusForbidden, "Forbidden"}
		}
	} else {
		var err error
		if document == nil {
			document, err = policy.Parse(result.PolicyDocument)
			if err != nil {
				return requestIdentity{}, invalid
			}
		}
		decision, err := EvaluateAuthorizerPolicy(document, executionARN(route, r.Method, executionPath(route, path)), r, s.clock.Now())
		if err != nil {
			return requestIdentity{}, invalid
		}
		if decision != policy.Allow {
			message := "Forbidden"
			if rest {
				message = "User is not authorized to access this resource"
				if decision == policy.ExplicitDeny {
					message += " with an explicit deny"
				}
			}
			return requestIdentity{}, &rejection{http.StatusForbidden, message}
		}
	}
	return requestIdentity{Lambda: &result, LambdaLatency: latency}, nil
}

// AuthorizerIdentities resolves configured sources using the protocol's value
// rules. WebSocket authorizers have no HTTP payload version and reject empty values.
func AuthorizerIdentities(r *http.Request, route *Route, path string, rest bool, protocolContext func(string) (string, bool)) ([]string, bool) {
	config := route.LambdaAuthorizer
	var identities []string
	for _, expression := range config.IdentitySources {
		var value string
		present := true
		switch {
		case strings.HasPrefix(expression, "method.request.header."), strings.HasPrefix(expression, "$request.header."), strings.HasPrefix(expression, "route.request.header."):
			_, name, _ := strings.Cut(expression, ".header.")
			values, ok := r.Header[http.CanonicalHeaderKey(name)]
			present = ok
			if len(values) > 0 {
				value = strings.Join(values, ",")
			}
		case strings.HasPrefix(expression, "method.request.querystring."), strings.HasPrefix(expression, "$request.querystring."), strings.HasPrefix(expression, "route.request.querystring."):
			_, name, _ := strings.Cut(expression, ".querystring.")
			values, ok := r.URL.Query()[name]
			present = ok
			if len(values) > 0 {
				value = values[len(values)-1]
				if !rest && config.PayloadVersion == "2.0" {
					value = strings.Join(values, ",")
				}
			}
		case strings.HasPrefix(expression, "stageVariables."), strings.HasPrefix(expression, "$stageVariables."):
			name := strings.TrimPrefix(strings.TrimPrefix(expression, "stageVariables."), "$stageVariables.")
			value, present = route.StageVariables[name]
		case strings.HasPrefix(expression, "context."), strings.HasPrefix(expression, "$context."):
			name := strings.TrimPrefix(strings.TrimPrefix(expression, "context."), "$context.")
			switch name {
			case "routeKey":
				value = route.RouteKey
			case "httpMethod":
				value = r.Method
			case "path":
				value = path
			case "resourcePath":
				value = route.ResourcePath
			case "stage":
				value = route.Stage
			case "apiId":
				value = route.APIID
			case "accountId":
				value = route.AccountID
			case "domainName":
				value = r.Host
			case "domainPrefix":
				value = route.APIID
			case "requestId":
				value = awsctx.FromContext(r.Context()).RequestID
			case "identity.sourceIp":
				value, _, _ = net.SplitHostPort(r.RemoteAddr)
				if value == "" {
					value = r.RemoteAddr
				}
			case "identity.userAgent":
				value = r.UserAgent()
			default:
				if protocolContext == nil {
					present = false
				} else {
					value, present = protocolContext(name)
				}
			}
		default:
			present = false
		}
		if !present || (rest || config.PayloadVersion == "") && value == "" {
			return nil, false
		}
		identities = append(identities, value)
	}
	return identities, true
}

func lambdaIntegrationContext(result *AuthorizerResult, config *LambdaAuthorizer, rest bool, latency int64) any {
	values := make(map[string]json.RawMessage, len(result.Context)+2)
	for name, value := range result.Context {
		if name == "claims" {
			continue
		}
		if rest || config.PayloadVersion == "1.0" {
			var text string
			if json.Unmarshal(value, &text) != nil {
				text = string(value)
			}
			values[name], _ = json.Marshal(text)
		} else {
			values[name] = value
		}
	}
	if rest {
		values["principalId"], _ = json.Marshal(result.PrincipalID)
		values["integrationLatency"] = json.RawMessage(strconv.FormatInt(latency, 10))
		return values
	}
	return struct {
		Lambda map[string]json.RawMessage `json:"lambda"`
	}{values}
}

func writeAuthorizerRejection(w http.ResponseWriter, rejected *rejection, rest bool) {
	if !rest {
		writeRejection(w, rejected)
		return
	}
	code := "AuthorizerConfigurationException"
	switch rejected.Status {
	case http.StatusUnauthorized:
		code = "UnauthorizedException"
	case http.StatusForbidden:
		code = "AccessDeniedException"
	}
	w.Header().Set("x-amzn-ErrorType", code)
	if rejected.Status == http.StatusUnauthorized {
		writeRejection(w, rejected)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rejected.Status)
	if rejected.Status == http.StatusInternalServerError {
		_ = json.NewEncoder(w).Encode(struct {
			Message *string `json:"message"`
		}{nil})
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Message string `json:"Message"`
	}{rejected.Message})
}
