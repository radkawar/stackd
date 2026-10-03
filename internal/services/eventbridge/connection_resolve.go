package eventbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
)

// ConnectionParameters preserves caller spelling for Step Functions' merge.
type ConnectionParameters struct{ Headers, Query, Body map[string]string }
type connectionToken struct {
	Version       uint64
	Authorization string
	Expires       time.Time
}
type connectionTokenCache struct {
	mu      sync.Mutex
	entries map[string]connectionToken
}

func (c *connectionTokenCache) get(v ConnectionRecord, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	token, ok := c.entries[v.ID]
	return token.Authorization, ok && token.Version == v.Version && token.Expires.After(now.Add(60*time.Second))
}
func (c *connectionTokenCache) put(v ConnectionRecord, token connectionToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]connectionToken{}
	}
	token.Version = v.Version
	c.entries[v.ID] = token
}
func (c *connectionTokenCache) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}
func connectionResourceError(code, message string) *awswire.Error {
	return failure("ConnectionResource."+code, message)
}
func parseConnectionARN(ctx context.Context, arn string) (ConnectionKey, string, *awswire.Error) {
	scope := scopeFor(ctx)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "events" || parts[3] != scope.Region || parts[4] != scope.Account {
		return ConnectionKey{}, "", connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
	}
	resource := strings.Split(parts[5], "/")
	if len(resource) != 3 || resource[0] != "connection" || resource[1] == "" || resource[2] == "" {
		return ConnectionKey{}, "", connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
	}
	return ConnectionKey{scope, resource[1]}, resource[2], nil
}
func (s *Service) ResolveConnection(ctx context.Context, arn string) (ConnectionParameters, *awswire.Error) {
	return s.resolveConnection(ctx, arn, false)
}

// ReauthorizeConnection is an optional HTTP consumer port for a provider's 401.
// Non-OAuth connections return their current credentials without token requests.
func (s *Service) ReauthorizeConnection(ctx context.Context, arn string) (ConnectionParameters, *awswire.Error) {
	return s.resolveConnection(ctx, arn, true)
}
func (s *Service) resolveConnection(ctx context.Context, arn string, refresh bool) (ConnectionParameters, *awswire.Error) {
	return s.resolveConnectionFor(ctx, arn, refresh, nil)
}

// connectionInvocation is internal to API destinations. Ordinary HTTP tasks
// retain execution-role RetrieveConnectionCredentials and secret permissions.
type connectionInvocation struct {
	connection ConnectionRecord
	authorize  func(Reader) error
}

func (i *connectionInvocation) failure(err error) *awswire.Error {
	if i != nil {
		return wireError(err)
	}
	return connectionResolutionError(err)
}

func (s *Service) resolveConnectionFor(ctx context.Context, arn string, refresh bool, invocation *connectionInvocation) (ConnectionParameters, *awswire.Error) {
	out := ConnectionParameters{}
	key, id, wire := parseConnectionARN(ctx, arn)
	if wire != nil {
		return out, wire
	}
	var v ConnectionRecord
	var c connectionSecret
	authorize := func(r Reader) error {
		if invocation != nil {
			return invocation.authorize(r)
		}
		if err := s.authorize(r, "RetrieveConnectionCredentials", arn, nil, nil, authorization.BoundPolicy{}); err != nil {
			return connectionResourceError("AccessDenied", "No permissions to call RetrieveConnectionCredentials on the connection resource.")
		}
		return nil
	}
	err := s.repository.Update(ctx, func(r Transaction) error {
		if err := authorize(r); err != nil {
			return err
		}
		var err error
		v, err = r.Connection(key)
		if errors.Is(err, ErrNotFound) || err == nil && v.ID != id {
			return connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
		}
		if err != nil {
			return err
		}
		if invocation != nil && (v.ID != invocation.connection.ID || v.Version != invocation.connection.Version) {
			return connectionResourceError("ConcurrentModification", "The connection was modified before invocation.")
		}
		if v.State == "AUTHORIZING" {
			return connectionResourceError("AuthInProgress", "Connection authorization is in progress.")
		}
		if v.State != "AUTHORIZED" || !v.HasAuth {
			return connectionResourceError("InvalidConnectionState", "The connection is not in an authorized state.")
		}
		if s.connectionSecrets == nil {
			return connectionResourceError("InternalError", "The connection secret store is unavailable.")
		}
		var body string
		var rejected *awswire.Error
		if invocation != nil {
			body, rejected = s.connectionSecrets.ReadOwned(r.Context(), v.ARN(), v.SecretARN)
		} else {
			body, rejected = s.connectionSecrets.ReadForInvocation(r.Context(), v.SecretARN)
		}
		if rejected != nil {
			if strings.Contains(rejected.Code, "AccessDenied") {
				return connectionResourceError("AccessDenied", "No permissions to call DescribeSecret and/or GetSecretValue on the secret associated with the connection resource.")
			}
			return connectionResourceError("InternalError", "Unable to retrieve the connection credentials.")
		}
		c, rejected = decodeConnectionSecret(body)
		if rejected != nil {
			return connectionResourceError("InternalError", rejected.Message)
		}
		return nil
	})
	if err != nil {
		return out, invocation.failure(err)
	}
	out = ConnectionParameters{Headers: map[string]string{}, Query: map[string]string{}, Body: map[string]string{}}
	if c.Invocation != nil {
		for _, p := range c.Invocation.Headers {
			key := p.Key
			if invocation != nil {
				key = http.CanonicalHeaderKey(key)
			}
			out.Headers[key] = p.Value
		}
		for _, p := range c.Invocation.Query {
			out.Query[p.Key] = p.Value
		}
		for _, p := range c.Invocation.Body {
			out.Body[p.Key] = p.Value
		}
	}
	switch v.AuthorizationType {
	case "BASIC":
		out.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	case "API_KEY":
		key := c.APIKeyName
		if invocation != nil {
			key = http.CanonicalHeaderKey(key)
		}
		out.Headers[key] = c.APIKeyValue
	case "OAUTH_CLIENT_CREDENTIALS":
		authorization, cached := s.connectionTokens.get(v, s.clock.Now())
		if refresh || !cached {
			token, rejected := s.acquireConnectionTokenFor(ctx, c, invocation != nil)
			var attempt *APIDestinationAttempt
			if rejected != nil && invocation != nil && errors.As(rejected, &attempt) {
				// A transient provider outage must not deauthorize the connection.
				return ConnectionParameters{}, rejected
			}
			var accepted bool
			var guard func(Reader) error
			if invocation != nil {
				guard = func(r Reader) error {
					if err := authorize(r); err != nil {
						return err
					}
					_, wire := s.connectionSecrets.ReadOwned(r.Context(), v.ARN(), v.SecretARN)
					if wire != nil {
						return wire
					}
					return nil
				}
			}
			v, accepted, err = s.finishConnectionAuthorizationGuarded(ctx, v, token, rejected, guard)
			if err != nil {
				return ConnectionParameters{}, invocation.failure(err)
			}
			if !accepted {
				return ConnectionParameters{}, connectionResourceError("ConcurrentModification", "The connection was modified during authorization.")
			}
			if rejected != nil {
				return ConnectionParameters{}, rejected
			}
			authorization = token.Authorization
		}
		out.Headers["Authorization"] = authorization
	default:
		return ConnectionParameters{}, connectionResourceError("InternalError", "The connection authorization type is not supported.")
	}
	// Fence a credentials read against deauthorization, deletion, replacement, and
	// policy changes while an actual token provider request was in flight.
	err = s.repository.View(ctx, func(r Reader) error {
		current, err := r.Connection(key)
		if errors.Is(err, ErrNotFound) || err == nil && current.ID != v.ID {
			return connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
		}
		if err != nil {
			return err
		}
		if current.Version != v.Version || current.State != "AUTHORIZED" {
			return connectionResourceError("ConcurrentModification", "The connection was modified during authorization.")
		}
		return authorize(r)
	})
	if err != nil {
		return ConnectionParameters{}, invocation.failure(err)
	}
	if invocation != nil {
		invocation.connection = v
	}
	return out, nil
}
func connectionResolutionError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) && strings.HasPrefix(wire.Code, "ConnectionResource.") {
		return wire
	}
	return connectionResourceError("InternalError", "Unable to access the connection resource.")
}
func (s *Service) acquireConnectionToken(ctx context.Context, c connectionSecret) (connectionToken, *awswire.Error) {
	return s.acquireConnectionTokenFor(ctx, c, false)
}

func (s *Service) acquireConnectionTokenFor(ctx context.Context, c connectionSecret, destination bool) (connectionToken, *awswire.Error) {
	bad := func(message string) (connectionToken, *awswire.Error) {
		return connectionToken{}, connectionResourceError("InvalidConnectionState", message)
	}
	endpoint, err := url.Parse(c.AuthorizationEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return bad("The OAuth authorization endpoint is invalid.")
	}
	query := endpoint.Query()
	form := url.Values{}
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Set("grant_type", "client_credentials")
	if c.OAuth != nil {
		for _, p := range c.OAuth.Headers {
			headers.Set(p.Key, p.Value)
		}
		for _, p := range c.OAuth.Query {
			query.Set(p.Key, p.Value)
		}
		for _, p := range c.OAuth.Body {
			form.Set(p.Key, p.Value)
		}
	}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	endpoint.RawQuery = query.Encode()
	requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, c.HTTPMethod, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return bad("Unable to construct the OAuth authorization request.")
	}
	request.Header = headers
	// Never forward provider credentials to a redirect target. Copy the injected
	// client so concurrent HTTP tasks retain their own redirect policy.
	client := *s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	response, err := client.Do(request)
	if err != nil {
		if destination {
			return connectionToken{}, apiDestinationTransportError(err)
		}
		return bad("Unable to connect to the OAuth authorization endpoint.")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if destination && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500) {
			return connectionToken{}, apiDestinationResponse(response.StatusCode, response.Header.Get("Retry-After"), s.clock.Now())
		}
		return bad("The OAuth authorization endpoint rejected the credentials.")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil && destination {
		return connectionToken{}, apiDestinationTransportError(err)
	}
	if err != nil || len(body) > 1<<20 {
		return bad("Unable to read the OAuth authorization response.")
	}
	var result struct {
		AccessToken string      `json:"access_token"`
		TokenType   string      `json:"token_type"`
		ExpiresIn   json.Number `json:"expires_in"`
	}
	if json.Unmarshal(body, &result) != nil || result.AccessToken == "" || strings.ContainsAny(result.AccessToken, "\r\n") {
		return bad("The OAuth authorization endpoint did not return a valid access token.")
	}
	if result.TokenType == "" {
		result.TokenType = "Bearer"
	}
	if !strings.EqualFold(result.TokenType, "Bearer") {
		return bad("The OAuth authorization endpoint returned an unsupported token type.")
	}
	// Without a provider expiry the token is usable for this request only, so a
	// restart or later invocation always reobtains credentials rather than guessing.
	expires := s.clock.Now()
	if result.ExpiresIn != "" {
		seconds, e := result.ExpiresIn.Int64()
		if e != nil || seconds <= 0 || seconds > int64((time.Duration(1<<63-1))/time.Second) {
			return bad("The OAuth authorization endpoint returned an invalid expiry.")
		}
		expires = expires.Add(time.Duration(seconds) * time.Second)
	}
	return connectionToken{Authorization: "Bearer " + result.AccessToken, Expires: expires}, nil
}
func (s *Service) finishConnectionAuthorization(ctx context.Context, v ConnectionRecord, token connectionToken, rejected *awswire.Error) (ConnectionRecord, bool, error) {
	return s.finishConnectionAuthorizationGuarded(ctx, v, token, rejected, nil)
}

func (s *Service) finishConnectionAuthorizationGuarded(ctx context.Context, v ConnectionRecord, token connectionToken, rejected *awswire.Error, guard func(Reader) error) (ConnectionRecord, bool, error) {
	accepted := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Connection(v.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != v.ID || current.Version != v.Version || !current.HasAuth || current.State != "AUTHORIZING" && current.State != "AUTHORIZED" {
			return nil
		}
		if guard != nil {
			if err := guard(tx); err != nil {
				return err
			}
		}
		current.Version++
		current.Due = time.Time{}
		if rejected != nil {
			current.State = "DEAUTHORIZED"
			current.StateReason = rejected.Message
		} else {
			current.State = "AUTHORIZED"
			current.StateReason = ""
			current.LastAuthorized = s.clock.Now().Truncate(time.Second)
			if v.State == "AUTHORIZING" {
				current.Modified = current.LastAuthorized
			}
		}
		if err := s.updateConnectionAPIDestinations(tx, v, current); err != nil {
			return err
		}
		if err := tx.PutConnection(current); err != nil {
			return err
		}
		v = current
		accepted = true
		return nil
	})
	if err == nil && accepted && rejected == nil {
		s.connectionTokens.put(v, token)
	}
	return v, accepted, err
}
