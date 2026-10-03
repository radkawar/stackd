package eventbridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

// APIDestinationAttempt carries scheduling information, not another retry owner.
// Admission means no endpoint request was made and must not consume a retry.
// RetryAfter is a minimum delay; StopRetry overrides the caller's retry policy.
// See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html.
type APIDestinationAttempt struct {
	RetryAfter time.Duration
	StopRetry  bool
	Admission  bool
}

func (*APIDestinationAttempt) Error() string { return "API destination attempt" }

// Retry hints let source delivery owners retain their own completion policies.
func (a *APIDestinationAttempt) RetryDelay() time.Duration { return a.RetryAfter }
func (a *APIDestinationAttempt) RetryStopped() bool        { return a.StopRetry }
func (a *APIDestinationAttempt) AdmissionDeferred() bool   { return a.Admission }

type apiDestinationCall struct {
	destinationID, connectionID string
	cancel                      context.CancelFunc
}

type apiDestinationCalls struct {
	mu     sync.Mutex
	active map[*apiDestinationCall]struct{}
	closed bool
}

func (s *Service) startAPIDestination(call *apiDestinationCall) bool {
	s.apiDestinationCalls.mu.Lock()
	defer s.apiDestinationCalls.mu.Unlock()
	if s.apiDestinationCalls.closed {
		call.cancel()
		return false
	}
	if s.apiDestinationCalls.active == nil {
		s.apiDestinationCalls.active = make(map[*apiDestinationCall]struct{})
	}
	s.apiDestinationCalls.active[call] = struct{}{}
	return true
}

func (s *Service) finishAPIDestination(call *apiDestinationCall) {
	call.cancel()
	s.apiDestinationCalls.mu.Lock()
	delete(s.apiDestinationCalls.active, call)
	s.apiDestinationCalls.mu.Unlock()
}

// cancelAPIDestination fences either a destination or a connection incarnation.
// Controls call it after committing the changed state. Registration precedes
// credential resolution, which rechecks both selected incarnations before use.
func (s *Service) cancelAPIDestination(id string) {
	s.apiDestinationCalls.mu.Lock()
	defer s.apiDestinationCalls.mu.Unlock()
	for call := range s.apiDestinationCalls.active {
		if call.destinationID == id || call.connectionID == id {
			call.cancel()
		}
	}
}

func (s *Service) closeAPIDestinations() {
	s.apiDestinationCalls.mu.Lock()
	defer s.apiDestinationCalls.mu.Unlock()
	s.apiDestinationCalls.closed = true
	for call := range s.apiDestinationCalls.active {
		call.cancel()
	}
}

func apiDestinationInvocationKey(ctx context.Context, arn string) (APIDestinationKey, string, *awswire.Error) {
	scope := scopeFor(ctx)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[1] == scope.Partition && parts[2] == "events" && parts[3] == scope.Region && parts[4] == scope.Account {
		resource := strings.Split(parts[5], "/")
		if len(resource) == 3 && resource[0] == "api-destination" && resource[1] != "" && resource[2] != "" {
			return APIDestinationKey{Scope: scope, Name: resource[1]}, resource[2], nil
		}
	}
	return APIDestinationKey{}, "", failure("ResourceNotFoundException", "The API destination does not exist.")
}

// InvokeAPIDestination is the shared rule/Pipes HTTP owner. It checks the current
// execution role against the exact destination, then obtains Connection secrets
// under the existing EventBridge service-linked role rather than that caller.
// A nonnil output receives the decoded successful enrichment response.
// Callers must discard it on error. A nil output drains without retaining bytes.
func (s *Service) InvokeAPIDestination(ctx context.Context, arn string, parameters *api.HttpParameters, payload string, output io.Writer) *awswire.Error {
	key, id, rejected := apiDestinationInvocationKey(ctx, arn)
	if rejected != nil {
		return rejected
	}
	// This single deadline includes credential acquisition, OAuth refresh, the
	// destination exchange and reading its response, even with an injected client.
	exchange, cancel := context.WithTimeout(ctx, 5*time.Second)
	call := &apiDestinationCall{destinationID: id, cancel: cancel}
	defer s.finishAPIDestination(call)
	var destination APIDestinationRecord
	var invocation connectionInvocation
	err := s.repository.View(exchange, func(r Reader) error {
		if err := s.authorize(r, "InvokeApiDestination", arn, nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		var err error
		destination, err = r.APIDestination(key)
		if errors.Is(err, ErrNotFound) || err == nil && destination.ID != id {
			return failure("ResourceNotFoundException", "The API destination does not exist.")
		}
		if err != nil {
			return err
		}
		connectionKey, connectionID, wire := parseConnectionARN(exchange, destination.ConnectionARN)
		if wire != nil {
			return wire
		}
		invocation.connection, err = r.Connection(connectionKey)
		if errors.Is(err, ErrNotFound) || err == nil && invocation.connection.ID != connectionID {
			return connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
		}
		if err != nil {
			return err
		}
		call.connectionID = connectionID
		if !s.startAPIDestination(call) {
			return failure("ServiceUnavailable", "API destination invocation is shutting down.", 503)
		}
		return nil
	})
	if err != nil {
		return apiDestinationInvocationError(exchange, err, false)
	}
	invocation.authorize = func(r Reader) error { return s.checkAPIDestination(r, destination) }
	resolved, rejected := s.resolveConnectionFor(exchange, destination.ConnectionARN, false, &invocation)
	if rejected != nil {
		return apiDestinationInvocationError(exchange, rejected, false)
	}
	request, rejected := apiDestinationRequest(exchange, destination, parameters, resolved, payload)
	if rejected != nil {
		return rejected
	}
	// Rate counters share the destination transaction domain and survive restart.
	// They do not change the configuration version used to fence active calls.
	err = s.repository.Update(exchange, func(tx Transaction) error {
		if err := s.checkAPIDestinationInvocation(tx, destination, invocation.connection); err != nil {
			return err
		}
		current, err := tx.APIDestination(key)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		if current.RateWindow.IsZero() || !now.Before(current.RateWindow.Add(time.Second)) || now.Before(current.RateWindow) {
			current.RateWindow = now.Truncate(time.Second)
			current.RateCount = 0
		}
		rate := current.Rate
		if rate == 0 {
			rate = defaultAPIDestinationRate
		}
		if current.RateCount >= rate {
			return &awswire.Error{Code: "ThrottlingException", Message: "The API destination invocation rate limit has been reached.", StatusCode: 429, Cause: &APIDestinationAttempt{Admission: true, RetryAfter: current.RateWindow.Add(time.Second).Sub(now)}}
		}
		current.RateCount++
		return tx.PutAPIDestination(current)
	})
	if err != nil {
		return apiDestinationInvocationError(exchange, err, false)
	}
	// A fresh request contains only admitted target/Connection parameters. Never
	// borrow inbound credentials, a shared cookie jar, or follow credential-bearing
	// redirects. Copying the client leaves all other consumers' settings intact.
	client := *s.httpClient
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return apiDestinationTransportError(err)
	}
	if rejected := readAPIDestinationResponse(response, output); rejected != nil {
		return rejected
	}
	err = s.repository.View(exchange, func(r Reader) error {
		return s.checkAPIDestinationInvocation(r, destination, invocation.connection)
	})
	if err != nil {
		return apiDestinationInvocationError(exchange, err, true)
	}
	rejected = apiDestinationResponse(response.StatusCode, response.Header.Get("Retry-After"), s.clock.Now())
	if rejected == nil {
		return nil
	}
	attempt := rejected.Cause.(*APIDestinationAttempt)
	if invocation.connection.AuthorizationType == "OAUTH_CLIENT_CREDENTIALS" && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusProxyAuthRequired) && !attempt.StopRetry {
		// Refresh for the retained next attempt, not a second unmetered delivery.
		// A successful token exchange is not a successful destination invocation.
		if _, wire := s.resolveConnectionFor(exchange, destination.ConnectionARN, true, &invocation); wire != nil {
			var providerAttempt *APIDestinationAttempt
			if errors.As(wire, &providerAttempt) {
				attempt.RetryAfter = max(attempt.RetryAfter, providerAttempt.RetryAfter)
				attempt.StopRetry = attempt.StopRetry || providerAttempt.StopRetry
				return rejected
			}
			if wire.Code == "ConnectionResource.InvalidConnectionState" {
				return rejected
			}
			refreshFailure := *apiDestinationInvocationError(exchange, wire, true)
			refreshFailure.Cause = attempt
			return &refreshFailure
		}
	}
	return rejected
}

func (s *Service) checkAPIDestination(r Reader, selected APIDestinationRecord) error {
	if err := s.authorize(r, "InvokeApiDestination", selected.ARN(), nil, nil, authorization.BoundPolicy{}); err != nil {
		return err
	}
	current, err := r.APIDestination(selected.Key)
	if errors.Is(err, ErrNotFound) || err == nil && current.ID != selected.ID {
		return failure("ResourceNotFoundException", "The API destination does not exist.")
	}
	if err != nil {
		return err
	}
	if current.Version != selected.Version {
		return failure("ConcurrentModificationException", "The API destination was modified during invocation.", 503)
	}
	return nil
}

func (s *Service) checkAPIDestinationInvocation(r Reader, destination APIDestinationRecord, connection ConnectionRecord) error {
	if err := s.checkAPIDestination(r, destination); err != nil {
		return err
	}
	current, err := r.Connection(connection.Key)
	if errors.Is(err, ErrNotFound) || err == nil && current.ID != connection.ID {
		return connectionResourceError("ResourceNotFound", "The connection resource does not exist.")
	}
	if err != nil {
		return err
	}
	if current.Version != connection.Version || current.State != "AUTHORIZED" || !current.HasAuth {
		return failure("ConnectionResource.ConcurrentModification", "The connection was modified during invocation.", 503)
	}
	return nil
}

func apiDestinationInvocationError(ctx context.Context, err error, invoked bool) *awswire.Error {
	if ctx.Err() != nil {
		return apiDestinationTransportError(ctx.Err())
	}
	rejected := wireError(err)
	if rejected.Code == "ConnectionResource.ConcurrentModification" {
		// Another consumer may have refreshed the same Connection version.
		// Retain the existing mutation/authority fence, but let the source retry
		// against current credentials instead of treating contention as terminal.
		// Before the endpoint call, no delivery attempt has been consumed.
		deferred := *rejected
		deferred.StatusCode = http.StatusServiceUnavailable
		deferred.Cause = &APIDestinationAttempt{Admission: !invoked, RetryAfter: time.Second}
		return &deferred
	}
	return rejected
}

func apiDestinationTransportError(err error) *awswire.Error {
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return &awswire.Error{Code: "RequestTimeout", Message: "The API destination request timed out.", StatusCode: 504, Cause: &APIDestinationAttempt{}}
	}
	return &awswire.Error{Code: "ServiceUnavailable", Message: "The API destination request could not be completed.", StatusCode: 503, Cause: &APIDestinationAttempt{}}
}

func apiDestinationRequest(ctx context.Context, destination APIDestinationRecord, parameters *api.HttpParameters, connection ConnectionParameters, payload string) (*http.Request, *awswire.Error) {
	invalid := func(message string) (*http.Request, *awswire.Error) {
		return nil, failure("InvalidParameterException", message)
	}
	address, err := url.Parse(destination.Endpoint)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.Fragment != "" {
		return invalid("The API destination endpoint must be an HTTPS URL without user information or a fragment.")
	}
	switch destination.Method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
	default:
		return invalid("The API destination HTTP method is invalid.")
	}
	var paths api.PathParameterList
	if parameters != nil {
		paths = parameters.PathParameterValues
	}
	path := address.EscapedPath()
	if strings.Count(path, "*") != len(paths) {
		return invalid("The number of path parameters must match the API destination path wildcards.")
	}
	if len(paths) != 0 {
		parts := strings.Split(path, "*")
		var substituted strings.Builder
		substituted.WriteString(parts[0])
		for i, value := range paths {
			substituted.WriteString(url.PathEscape(string(value)))
			substituted.WriteString(parts[i+1])
		}
		address.RawPath = substituted.String()
		address.Path, err = url.PathUnescape(address.RawPath)
		if err != nil {
			return invalid("The API destination path parameters are invalid.")
		}
	}
	query := address.Query()
	headers := http.Header{}
	if parameters != nil {
		for key, value := range parameters.QueryStringParameters {
			query.Set(string(key), string(value))
		}
		for _, key := range slices.Sorted(maps.Keys(parameters.HeaderParameters)) {
			headers.Add(string(key), string(parameters.HeaderParameters[key]))
		}
	}
	for key, value := range connection.Query {
		query.Set(key, value)
	}
	for key, value := range connection.Headers {
		headers.Set(key, value)
	}
	address.RawQuery = query.Encode()
	if len(connection.Body) != 0 {
		body := make(map[string]json.RawMessage)
		if payload != "" && (json.Unmarshal([]byte(payload), &body) != nil || body == nil) {
			return invalid("Connection body parameters require a JSON object payload.")
		}
		for key, value := range connection.Body {
			body[key], _ = json.Marshal(value)
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return invalid("The API destination request body is invalid.")
		}
		payload = string(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, destination.Method, address.String(), strings.NewReader(payload))
	if err != nil {
		return invalid("Unable to construct the API destination request.")
	}
	for key := range headers {
		if apiDestinationRemovedHeader(key) {
			delete(headers, key)
		}
	}
	headers.Set("User-Agent", "Amazon/EventBridge/ApiDestinations")
	headers.Set("Range", "bytes=0-1048575")
	headers.Set("Accept-Encoding", "gzip,deflate")
	headers.Set("Connection", "close")
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json; charset=utf-8")
	}
	request.Header = headers
	request.Close = true
	return request, nil
}

func apiDestinationRemovedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "a-im", "accept-charset", "accept-datetime", "accept-encoding", "cache-control", "connection", "content-encoding", "content-length", "content-md5", "date", "expect", "forwarded", "from", "host", "http2-settings", "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since", "max-forwards", "origin", "pragma", "proxy-authorization", "range", "referer", "te", "trailer", "transfer-encoding", "user-agent", "upgrade", "via", "warning":
		return true
	}
	return false
}

func apiDestinationResponse(status int, retryAfter string, now time.Time) *awswire.Error {
	if status >= 200 && status < 300 {
		return nil
	}
	attempt := &APIDestinationAttempt{}
	wireStatus := 400
	if status == 401 || status == 407 || status == 409 || status == 429 || status >= 500 && status < 600 {
		wireStatus = 502
	} else {
		attempt.StopRetry = true
	}
	retryAfter = strings.TrimSpace(retryAfter)
	seconds, err := strconv.ParseInt(retryAfter, 10, 64)
	if err == nil || errors.Is(err, strconv.ErrRange) {
		if seconds < 0 {
			attempt.StopRetry = true
		} else {
			const maximum = time.Duration(1<<63 - 1)
			if seconds > int64(maximum/time.Second) {
				attempt.RetryAfter = maximum
			} else {
				attempt.RetryAfter = time.Duration(seconds) * time.Second
			}
		}
	} else if date, err := http.ParseTime(retryAfter); err == nil && date.After(now) {
		attempt.RetryAfter = date.Sub(now)
	}
	return &awswire.Error{Code: "HTTPStatus" + strconv.Itoa(status), Message: "The API destination returned HTTP status " + strconv.Itoa(status) + ".", StatusCode: wireStatus, Cause: attempt}
}
