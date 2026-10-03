package sts

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stackd/clock"
	"stackd/internal/awswire"
	"stackd/internal/jwt"
)

// OAuthHTTPConfig explicitly selects the HTTP dependency for opaque social
// access tokens. Facebook requires an app access token authorized to inspect
// the submitted user token. Endpoint overrides support controlled test IdPs.
type OAuthHTTPConfig struct {
	Client                                    *http.Client
	AmazonTokenInfoURL, FacebookDebugTokenURL string
	FacebookAppAccessToken                    string
	// Clock checks provider token expiry. HTTP deadlines and TLS use real time.
	Clock clock.Clock
}
type httpOAuthTokens struct {
	client           *http.Client
	amazon, facebook string
	facebookAppToken string
	now              func() time.Time
}

// NewHTTPOAuthTokenSource enables provider-side token introspection explicitly.
// Redirects are rejected so neither submitted nor configured tokens can move to
// an endpoint that was not configured by the application.
func NewHTTPOAuthTokenSource(config OAuthHTTPConfig) (OAuthTokenSource, error) {
	if config.AmazonTokenInfoURL == "" {
		config.AmazonTokenInfoURL = "https://api.amazon.com/auth/o2/tokeninfo"
	}
	if config.FacebookDebugTokenURL == "" {
		config.FacebookDebugTokenURL = "https://graph.facebook.com/debug_token"
	}
	for _, endpoint := range []string{config.AmazonTokenInfoURL, config.FacebookDebugTokenURL} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
			return nil, stsValidation("OAuth introspection requires a configured HTTPS URL without credentials, query or fragment.")
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if config.Client != nil {
		copy := *config.Client
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	return &httpOAuthTokens{client: client, amazon: config.AmazonTokenInfoURL, facebook: config.FacebookDebugTokenURL, facebookAppToken: config.FacebookAppAccessToken, now: config.Clock.Now}, nil
}
func (s *httpOAuthTokens) VerifyOAuthAccessToken(ctx context.Context, provider, token string) (OAuthIdentity, error) {
	if token == "" {
		return OAuthIdentity{}, invalidOIDCToken("The access token is empty.")
	}
	var endpoint string
	params := url.Values{}
	switch provider {
	case "www.amazon.com":
		endpoint = s.amazon
		params.Set("access_token", token)
	case "graph.facebook.com":
		if s.facebookAppToken == "" {
			return OAuthIdentity{}, oidcProviderError("Facebook token introspection credentials are not configured.")
		}
		endpoint = s.facebook
		params.Set("input_token", token)
		params.Set("access_token", s.facebookAppToken)
	default:
		return OAuthIdentity{}, invalidOIDCToken("The OAuth identity provider is not supported.")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return OAuthIdentity{}, oidcProviderError("Unable to construct the provider verification request.")
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return OAuthIdentity{}, oidcProviderError("Unable to contact the OAuth identity provider.")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		if provider == "graph.facebook.com" {
			return OAuthIdentity{}, &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Facebook identity provider rejected the OAuth token."}
		}
		return OAuthIdentity{}, invalidOIDCToken("The OAuth identity provider rejected the token.")
	}
	if response.StatusCode != http.StatusOK {
		return OAuthIdentity{}, oidcProviderError("The OAuth identity provider returned an unsuccessful response.")
	}
	const maximum = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(data) > maximum {
		return OAuthIdentity{}, oidcProviderError("Unable to read the OAuth identity provider response.")
	}
	object, err := jwt.Object(data)
	if err != nil {
		return OAuthIdentity{}, invalidOIDCToken("The OAuth verification response is malformed.")
	}
	if _, exists := object["error"]; exists {
		if provider == "graph.facebook.com" {
			return OAuthIdentity{}, &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Facebook identity provider rejected the OAuth token."}
		}
		return OAuthIdentity{}, invalidOIDCToken("The OAuth identity provider rejected the token.")
	}
	if provider == "www.amazon.com" {
		return s.amazonIdentity(object)
	}
	return s.facebookIdentity(object)
}
func (s *httpOAuthTokens) amazonIdentity(object map[string]json.RawMessage) (OAuthIdentity, error) {
	issuer, issuerOK := jwt.String(object, "iss")
	subject, subjectOK := jwt.String(object, "user_id")
	audience, audienceOK := jwt.String(object, "aud")
	application, applicationOK := jwt.String(object, "app_id")
	expires, err := oidcTimestamp(object["exp"])
	// Amazon tokeninfo reports exp as the number of remaining seconds, unlike
	// the absolute NumericDate used inside OIDC ID tokens.
	if !issuerOK || issuer != "https://www.amazon.com" || !subjectOK || subject == "" || !audienceOK || audience == "" || !applicationOK || application == "" || err != nil {
		return OAuthIdentity{}, invalidOIDCToken("The Amazon verification response is missing required claims.")
	}
	if expires.Unix() <= 0 {
		return OAuthIdentity{}, &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Amazon access token has expired."}
	}
	if expires.Unix() > math.MaxInt64/int64(time.Second) {
		return OAuthIdentity{}, invalidOIDCToken("The Amazon verification response has an invalid token lifetime.")
	}
	deadline := s.now().Add(time.Duration(expires.Unix()) * time.Second)
	values := map[string][]string{"www.amazon.com:app_id": {application}, "www.amazon.com:sub": {subject}, "www.amazon.com:user_id": {subject}}
	return OAuthIdentity{ProviderID: "www.amazon.com", Subject: subject, Audience: audience, TrustContext: values, SessionContext: cloneOIDCContext(values), ExpiresAt: &deadline}, nil
}
func (s *httpOAuthTokens) facebookIdentity(object map[string]json.RawMessage) (OAuthIdentity, error) {
	data, err := jwt.Object(object["data"])
	if err != nil {
		return OAuthIdentity{}, invalidOIDCToken("The Facebook verification response is malformed.")
	}
	var valid bool
	if json.Unmarshal(data["is_valid"], &valid) != nil || !valid {
		return OAuthIdentity{}, &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Facebook access token is no longer valid."}
	}
	subject, subjectOK := jwt.String(data, "user_id")
	application, applicationOK := jwt.String(data, "app_id")
	if !subjectOK || subject == "" || !applicationOK || application == "" {
		return OAuthIdentity{}, invalidOIDCToken("The Facebook verification response is missing required claims.")
	}
	now := s.now()
	var deadline *time.Time
	for _, name := range []string{"expires_at", "data_access_expires_at"} {
		if raw, exists := data[name]; exists {
			expires, err := oidcTimestamp(raw)
			if err != nil {
				return OAuthIdentity{}, invalidOIDCToken("The Facebook verification response has an invalid timestamp.")
			}
			if expires.Unix() != 0 {
				if !now.Before(expires) {
					return OAuthIdentity{}, &awswire.Error{Code: "IDPRejectedClaim", StatusCode: 403, Message: "The Facebook access token has expired."}
				}
				if deadline == nil || expires.Before(*deadline) {
					deadline = &expires
				}
			}
		}
	}
	if raw, exists := data["type"]; exists {
		var kind string
		if json.Unmarshal(raw, &kind) != nil || !strings.EqualFold(kind, "USER") {
			return OAuthIdentity{}, invalidOIDCToken("Facebook web identity requires a user access token.")
		}
	}
	values := map[string][]string{"graph.facebook.com:app_id": {application}, "graph.facebook.com:id": {subject}}
	return OAuthIdentity{ProviderID: "graph.facebook.com", Subject: subject, Audience: application, TrustContext: values, SessionContext: cloneOIDCContext(values), ExpiresAt: deadline}, nil
}
func cloneOIDCContext(values map[string][]string) map[string][]string {
	result := make(map[string][]string, len(values))
	for key, value := range values {
		result[key] = append([]string(nil), value...)
	}
	return result
}
