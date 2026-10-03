package eventbridge

import (
	"encoding/json"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

// These are the native managed SecretString documents, never repository DTOs.
type connectionSecret struct {
	Username              string                `json:"username,omitempty"`
	Password              string                `json:"password,omitempty"`
	APIKeyName            string                `json:"api_key_name,omitempty"`
	APIKeyValue           string                `json:"api_key_value,omitempty"`
	ClientID              string                `json:"client_id,omitempty"`
	ClientSecret          string                `json:"client_secret,omitempty"`
	AuthorizationEndpoint string                `json:"authorization_endpoint,omitempty"`
	HTTPMethod            string                `json:"http_method,omitempty"`
	OAuth                 *connectionSecretHTTP `json:"oauth_http_parameters,omitempty"`
	Invocation            *connectionSecretHTTP `json:"invocation_http_parameters,omitempty"`
}
type connectionSecretHTTP struct {
	Headers []connectionSecretParameter `json:"header_parameters,omitempty"`
	Query   []connectionSecretParameter `json:"query_string_parameters,omitempty"`
	Body    []connectionSecretParameter `json:"body_parameters,omitempty"`
}
type connectionSecretParameter struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"is_value_secret"`
}

func connectionAuthError(message string) *awswire.Error {
	return failure("ValidationException", message)
}
func connectionPrivateUnsupported() *awswire.Error {
	// TODO: Comeback implement EventBridge Connection private connectivity and resource associations.
	return unsupported("EventBridge Connection private connectivity is not implemented.")
}
func connectionAuthValid(kind string, c connectionSecret) *awswire.Error {
	switch kind {
	case "BASIC":
		if c.Username == "" || c.Password == "" {
			return connectionAuthError("BasicAuthParameters must include Username and Password.")
		}
	case "API_KEY":
		if c.APIKeyName == "" || c.APIKeyValue == "" {
			return connectionAuthError("ApiKeyAuthParameters must include ApiKeyName and ApiKeyValue.")
		}
	case "OAUTH_CLIENT_CREDENTIALS":
		if c.ClientID == "" || c.ClientSecret == "" || c.AuthorizationEndpoint == "" || c.HTTPMethod == "" {
			return connectionAuthError("OAuthParameters must include AuthorizationEndpoint, HttpMethod, ClientID and ClientSecret.")
		}
		endpoint, err := url.Parse(c.AuthorizationEndpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
			return connectionAuthError("AuthorizationEndpoint must be a valid HTTPS endpoint.")
		}
		if c.HTTPMethod != "GET" && c.HTTPMethod != "POST" && c.HTTPMethod != "PUT" {
			return connectionAuthError("OAuth HttpMethod must be GET, POST or PUT.")
		}
	default:
		return connectionAuthError("AuthorizationType must be BASIC, API_KEY, or OAUTH_CLIENT_CREDENTIALS.")
	}
	return nil
}
func secretHTTP(in *api.ConnectionHttpParameters, old *connectionSecretHTTP) (*connectionSecretHTTP, *awswire.Error) {
	if in == nil {
		return old, nil
	}
	out := connectionSecretHTTP{}
	if old != nil {
		out = *old
	}
	merge := func(key, val string, present, secret bool, prior []connectionSecretParameter) (connectionSecretParameter, *awswire.Error) {
		if key == "" {
			return connectionSecretParameter{}, connectionAuthError("HTTP parameter Key must not be empty.")
		}
		if !present {
			for _, p := range prior {
				if p.Key == key {
					val = p.Value
					break
				}
			}
		}
		return connectionSecretParameter{key, val, secret}, nil
	}
	if in.HeaderParameters != nil {
		out.Headers = make([]connectionSecretParameter, 0, len(in.HeaderParameters))
		for _, p := range in.HeaderParameters {
			v, e := merge(value(p.Key), value(p.Value), p.Value != nil, p.IsValueSecret != nil && bool(*p.IsValueSecret), outPrior(old, "header"))
			if e != nil {
				return nil, e
			}
			if strings.ContainsAny(v.Key+v.Value, "\r\n") {
				return nil, connectionAuthError("HTTP header parameters cannot contain line breaks.")
			}
			out.Headers = append(out.Headers, v)
		}
	}
	if in.QueryStringParameters != nil {
		out.Query = make([]connectionSecretParameter, 0, len(in.QueryStringParameters))
		for _, p := range in.QueryStringParameters {
			v, e := merge(value(p.Key), value(p.Value), p.Value != nil, p.IsValueSecret != nil && bool(*p.IsValueSecret), outPrior(old, "query"))
			if e != nil {
				return nil, e
			}
			out.Query = append(out.Query, v)
		}
	}
	if in.BodyParameters != nil {
		out.Body = make([]connectionSecretParameter, 0, len(in.BodyParameters))
		for _, p := range in.BodyParameters {
			v, e := merge(value(p.Key), value(p.Value), p.Value != nil, p.IsValueSecret != nil && bool(*p.IsValueSecret), outPrior(old, "body"))
			if e != nil {
				return nil, e
			}
			out.Body = append(out.Body, v)
		}
	}
	return &out, nil
}
func outPrior(v *connectionSecretHTTP, location string) []connectionSecretParameter {
	if v == nil {
		return nil
	}
	switch location {
	case "header":
		return v.Headers
	case "query":
		return v.Query
	default:
		return v.Body
	}
}
func createConnectionSecret(kind string, in *api.CreateConnectionAuthRequestParameters) (connectionSecret, *awswire.Error) {
	c := connectionSecret{}
	if in == nil {
		return c, connectionAuthError("AuthParameters is required.")
	}
	if in.ConnectivityParameters != nil {
		return c, connectionPrivateUnsupported()
	}
	count := 0
	if p := in.BasicAuthParameters; p != nil {
		count++
		if kind != "BASIC" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		c.Username, c.Password = value(p.Username), value(p.Password)
	}
	if p := in.ApiKeyAuthParameters; p != nil {
		count++
		if kind != "API_KEY" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		c.APIKeyName, c.APIKeyValue = value(p.ApiKeyName), value(p.ApiKeyValue)
	}
	if p := in.OAuthParameters; p != nil {
		count++
		if kind != "OAUTH_CLIENT_CREDENTIALS" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		c.AuthorizationEndpoint, c.HTTPMethod = value(p.AuthorizationEndpoint), value(p.HttpMethod)
		if p.ClientParameters != nil {
			c.ClientID, c.ClientSecret = value(p.ClientParameters.ClientID), value(p.ClientParameters.ClientSecret)
		}
		var e *awswire.Error
		c.OAuth, e = secretHTTP(p.OAuthHttpParameters, nil)
		if e != nil {
			return c, e
		}
	}
	if count != 1 {
		return c, connectionAuthError("Exactly one authentication parameter type is required.")
	}
	var e *awswire.Error
	c.Invocation, e = secretHTTP(in.InvocationHttpParameters, nil)
	if e != nil {
		return c, e
	}
	return c, connectionAuthValid(kind, c)
}
func updateConnectionSecret(kind string, in *api.UpdateConnectionAuthRequestParameters, c connectionSecret) (connectionSecret, *awswire.Error) {
	if in == nil {
		return c, connectionAuthValid(kind, c)
	}
	if in.ConnectivityParameters != nil {
		return c, connectionPrivateUnsupported()
	}
	if p := in.BasicAuthParameters; p != nil {
		if kind != "BASIC" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		if p.Username != nil {
			c.Username = value(p.Username)
		}
		if p.Password != nil {
			c.Password = value(p.Password)
		}
	}
	if p := in.ApiKeyAuthParameters; p != nil {
		if kind != "API_KEY" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		if p.ApiKeyName != nil {
			c.APIKeyName = value(p.ApiKeyName)
		}
		if p.ApiKeyValue != nil {
			c.APIKeyValue = value(p.ApiKeyValue)
		}
	}
	if p := in.OAuthParameters; p != nil {
		if kind != "OAUTH_CLIENT_CREDENTIALS" {
			return c, connectionAuthError("AuthorizationType does not match AuthParameters.")
		}
		if p.AuthorizationEndpoint != nil {
			c.AuthorizationEndpoint = value(p.AuthorizationEndpoint)
		}
		if p.HttpMethod != nil {
			c.HTTPMethod = value(p.HttpMethod)
		}
		if p.ClientParameters != nil {
			if p.ClientParameters.ClientID != nil {
				c.ClientID = value(p.ClientParameters.ClientID)
			}
			if p.ClientParameters.ClientSecret != nil {
				c.ClientSecret = value(p.ClientParameters.ClientSecret)
			}
		}
		var e *awswire.Error
		c.OAuth, e = secretHTTP(p.OAuthHttpParameters, c.OAuth)
		if e != nil {
			return c, e
		}
	}
	var e *awswire.Error
	c.Invocation, e = secretHTTP(in.InvocationHttpParameters, c.Invocation)
	if e != nil {
		return c, e
	}
	return c, connectionAuthValid(kind, c)
}
func projectConnectionSecret(v *ConnectionRecord, c connectionSecret) {
	v.HasAuth = true
	v.Username, v.APIKeyName, v.ClientID = c.Username, c.APIKeyName, c.ClientID
	v.AuthorizationEndpoint, v.OAuthMethod = c.AuthorizationEndpoint, c.HTTPMethod
	v.HasInvocation, v.HasOAuthHTTP = c.Invocation != nil, c.OAuth != nil
	v.Parameters = nil
	add := func(target, location string, rows []connectionSecretParameter) {
		for _, p := range rows {
			public := p.Value
			if p.Secret {
				public = ""
			}
			v.Parameters = append(v.Parameters, ConnectionParameter{target, location, p.Key, public, p.Secret})
		}
	}
	if c.Invocation != nil {
		add("invocation", "header", c.Invocation.Headers)
		add("invocation", "query", c.Invocation.Query)
		add("invocation", "body", c.Invocation.Body)
	}
	if c.OAuth != nil {
		add("oauth", "header", c.OAuth.Headers)
		add("oauth", "query", c.OAuth.Query)
		add("oauth", "body", c.OAuth.Body)
	}
}
func publicConnectionHTTP(v ConnectionRecord, target string) *api.ConnectionHttpParameters {
	out := &api.ConnectionHttpParameters{}
	for _, p := range v.Parameters {
		if p.Target != target {
			continue
		}
		secret := ptr(api.Boolean(p.Secret))
		switch p.Location {
		case "header":
			q := api.ConnectionHeaderParameter{Key: str[api.HeaderKey](p.Key), IsValueSecret: secret}
			if !p.Secret {
				q.Value = str[api.HeaderValueSensitive](p.Value)
			}
			out.HeaderParameters = append(out.HeaderParameters, q)
		case "query":
			q := api.ConnectionQueryStringParameter{Key: str[api.QueryStringKey](p.Key), IsValueSecret: secret}
			if !p.Secret {
				q.Value = str[api.QueryStringValueSensitive](p.Value)
			}
			out.QueryStringParameters = append(out.QueryStringParameters, q)
		case "body":
			q := api.ConnectionBodyParameter{Key: str[api.String](p.Key), IsValueSecret: secret}
			if !p.Secret {
				q.Value = str[api.SensitiveString](p.Value)
			}
			out.BodyParameters = append(out.BodyParameters, q)
		}
	}
	return out
}
func publicConnectionAuth(v ConnectionRecord) *api.ConnectionAuthResponseParameters {
	out := &api.ConnectionAuthResponseParameters{}
	if !v.HasAuth {
		return out
	}
	switch v.AuthorizationType {
	case "BASIC":
		out.BasicAuthParameters = &api.ConnectionBasicAuthResponseParameters{Username: str[api.AuthHeaderParameters](v.Username)}
	case "API_KEY":
		out.ApiKeyAuthParameters = &api.ConnectionApiKeyAuthResponseParameters{ApiKeyName: str[api.AuthHeaderParameters](v.APIKeyName)}
	case "OAUTH_CLIENT_CREDENTIALS":
		out.OAuthParameters = &api.ConnectionOAuthResponseParameters{AuthorizationEndpoint: str[api.HttpsEndpoint](v.AuthorizationEndpoint), HttpMethod: str[api.ConnectionOAuthHttpMethod](v.OAuthMethod), ClientParameters: &api.ConnectionOAuthClientResponseParameters{ClientID: str[api.AuthHeaderParameters](v.ClientID)}}
		if v.HasOAuthHTTP {
			out.OAuthParameters.OAuthHttpParameters = publicConnectionHTTP(v, "oauth")
		}
	}
	if v.HasInvocation {
		out.InvocationHttpParameters = publicConnectionHTTP(v, "invocation")
	}
	return out
}
func encodeConnectionSecret(c connectionSecret) (string, *awswire.Error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", failure("InternalException", "Unable to encode connection credentials.", 500)
	}
	return string(b), nil
}
func decodeConnectionSecret(body string) (connectionSecret, *awswire.Error) {
	var c connectionSecret
	if json.Unmarshal([]byte(body), &c) != nil {
		return c, failure("InternalException", "Unable to decode connection credentials.", 500)
	}
	return c, nil
}
