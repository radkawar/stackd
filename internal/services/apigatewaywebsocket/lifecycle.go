package apigatewaywebsocket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/google/uuid"
	"stackd/internal/authorization"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

type proxyResponse struct {
	StatusCode        *int                `json:"statusCode"`
	Headers           map[string]string   `json:"headers"`
	MultiValueHeaders map[string][]string `json:"multiValueHeaders"`
	Body              string              `json:"body"`
	IsBase64Encoded   bool                `json:"isBase64Encoded"`
}

func (s *Service) connect(w http.ResponseWriter, r *http.Request, route *apigatewayexec.Route) {
	now := s.clock.Now()
	ctx, cancel := context.WithCancel(s.ctx)
	c := &connection{service: s, endpoint: owner(route), id: uuid.NewString(), domain: r.Host,
		identity: requestIdentity(r), connectedAt: now, lastActive: now,
		ctx: ctx, cancel: cancel, writeGate: make(chan struct{}, 1), activity: make(chan struct{}, 1),
		caller: awsctx.FromContext(r.Context())}
	c.writeGate <- struct{}{}
	payload := c.connectEvent(r, route, now)
	logs := s.newEventLog(route, payload.RequestContext)
	metrics := eventMetrics{}
	defer func() { s.recordLogs(r.Context(), route, now, payload.RequestContext, c.caller, metrics, logs) }()
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		cancel()
		logs.failure(forbidden(), "ACCESS_DENIED")
		writeExecutionError(w, forbidden())
		return
	}
	switch route.AuthorizationType {
	case "", "NONE", "CUSTOM":
	case "AWS_IAM":
		if rejected := s.authorization.Authorize(r.Context(), authorization.Request{
			Action: "execute-api:Invoke", ResourceARN: owner(route).arn("$connect"), ResourceAccountID: route.AccountID,
		}); rejected != nil {
			cancel()
			logs.failure(forbidden(), "ACCESS_DENIED")
			writeExecutionError(w, forbidden())
			return
		}
	default:
		cancel()
		logs.failure(forbidden(), "ACCESS_DENIED")
		writeExecutionError(w, forbidden())
		return
	}
	if route.AuthorizationType == "CUSTOM" && !c.authorize(w, r, route, &payload, &logs) {
		cancel()
		return
	}
	metrics = eventMetrics{connect: true, messages: 1}
	defer func() { s.recordMetrics(r.Context(), route, now, metrics) }()
	if route.FunctionARN != "" {
		result, rejected := s.invoke(r.Context(), route, payload, c.caller, &metrics, &logs)
		if rejected != nil {
			cancel()
			c.rejectConnect(w, payload.RequestContext.RequestID, rejected.StatusCode, rejected.Message)
			return
		}
		if *result.StatusCode < 200 || *result.StatusCode >= 300 {
			cancel()
			writeConnectResponse(w, result)
			return
		}
	}
	if err := r.Context().Err(); err != nil || s.ctx.Err() != nil {
		metrics.responseStatus(http.StatusServiceUnavailable)
		logs.failure(unavailable(), "DEFAULT_5XX")
		cancel()
		writeExecutionError(w, unavailable())
		return
	}
	upgrader := ws.HTTPUpgrader{Timeout: writeTimeout}
	conn, buffered, _, err := upgrader.Upgrade(r, w)
	if err != nil {
		logs.failure(failure("BadRequestException", "WebSocket upgrade failed", http.StatusBadRequest), "BAD_REQUEST_BODY")
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	c.socket = conn
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		logs.failure(unavailable(), "DEFAULT_5XX")
		_ = conn.Close()
		return
	}
	s.connections[c.endpoint.connectionKey(c.id)] = c
	s.workers.Add(2)
	s.mu.Unlock()
	go c.readMessages(buffered.Reader)
	go c.expire()
}

func (s *Service) invoke(ctx context.Context, route *apigatewayexec.Route, payload event, caller awsctx.Metadata, metrics *eventMetrics, logs *eventLog) (_ *proxyResponse, rejected *awswire.Error) {
	metrics.executionError = true
	bad := failure("InternalServerErrorException", "Internal server error", http.StatusInternalServerError)
	responseType := "INTEGRATION_FAILURE"
	defer func() {
		if rejected != nil {
			logs.failure(rejected, responseType)
		}
	}()
	if s.functions == nil {
		return nil, bad
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, bad
	}
	metadata := awsctx.Metadata{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region,
		RequestID: payload.RequestContext.RequestID, ParentEventID: caller.ParentEventID, TraceHeader: caller.TraceHeader,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "apigateway.amazonaws.com", SourceARN: owner(route).arn(payload.RequestContext.RouteKey), Type: "Service"},
		InvokedBy:        "apigateway.amazonaws.com"}
	ctx = awsctx.WithMetadata(ctx, metadata)
	timeout := integrationTimeout
	if route.IntegrationTimeoutMillis > 0 {
		timeout = time.Duration(route.IntegrationTimeoutMillis) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	var roleFailure *awswire.Error
	ctx, roleFailure = apigatewayexec.IntegrationContext(ctx, route.IntegrationCredentialsARN, s.roles, caller, false)
	if roleFailure != nil {
		responseType = "API_CONFIGURATION_ERROR"
		logs.executionError("Execution failed due to integration credentials: %s", roleFailure.Message)
		return nil, bad
	}
	name := lambdaapi.NamespacedFunctionName(route.FunctionARN)
	if logs.dataTrace {
		logs.information("Endpoint request body after transformations: %s", apigatewayexec.RedactExecutionLogPayload(body))
	}
	started := time.Now()
	output, endpointRequestID, rejected := s.functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: &name, Payload: lambdaapi.Blob(body)})
	logs.endpointRequestID = endpointRequestID
	metrics.integrationLatency = time.Since(started)
	metrics.integrationCalled = true
	if endpointRequestID != "" {
		logs.information("AWS Integration Endpoint RequestId : %s", endpointRequestID)
	}
	if output != nil && logs.dataTrace {
		if output.StatusCode != nil {
			logs.information("Received response. Status: %d, Integration latency: %d ms", *output.StatusCode, metrics.integrationLatency.Milliseconds())
		}
		logs.information("Endpoint response body before transformations: %s", apigatewayexec.RedactExecutionLogPayload(output.Payload))
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		responseType = "INTEGRATION_TIMEOUT"
		return nil, failure("IntegrationTimeoutException", "Endpoint request timed out", http.StatusGatewayTimeout)
	}
	if ctx.Err() != nil || rejected != nil || output == nil {
		return nil, bad
	}
	if output.FunctionError != nil {
		if logs.errors {
			var details struct {
				Message string `json:"errorMessage"`
			}
			_ = json.Unmarshal(output.Payload, &details)
			logs.executionError("Lambda execution failed due to customer function error: %s. Lambda request id: %s", details.Message, endpointRequestID)
		}
		return nil, failure("InternalServerErrorException", "Internal server error", http.StatusBadGateway)
	}
	var result proxyResponse
	if json.Unmarshal(output.Payload, &result) != nil || result.StatusCode == nil || *result.StatusCode < 100 || *result.StatusCode > 599 {
		return nil, bad
	}
	if result.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil {
			return nil, bad
		}
		result.Body = string(decoded)
	}
	metrics.responseStatus(*result.StatusCode)
	logs.status = *result.StatusCode
	if logs.status >= http.StatusBadRequest {
		logs.executionError("Integration returned status: %d", logs.status)
	}
	return &result, nil
}

func writeConnectResponse(w http.ResponseWriter, result *proxyResponse) {
	for key, value := range result.Headers {
		if responseHeader(key) {
			w.Header().Set(key, value)
		}
	}
	for key, values := range result.MultiValueHeaders {
		if !responseHeader(key) {
			continue
		}
		w.Header().Del(key)
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(*result.StatusCode)
	_, _ = w.Write([]byte(result.Body))
}

func responseHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "upgrade", "content-length", "transfer-encoding", "sec-websocket-accept":
		return false
	}
	return true
}

func (c *connection) message(body []byte) {
	now := c.service.clock.Now()
	route, err := c.service.resolver.ResolveWebSocket(c.ctx, c.endpoint.api, c.endpoint.stage, "", body)
	if c.ctx.Err() != nil {
		return
	}
	metrics := eventMetrics{}
	if route == nil || owner(route) != c.endpoint {
		// There is no resolved stage authority for publishing logs. The error
		// frame still owns its request ID rather than borrowing an invocation ID.
		c.gatewayError("Internal server error", uuid.NewString(), nil)
		return
	}
	payload := c.messageEvent(route, body, now)
	logs := c.service.newEventLog(route, payload.RequestContext)
	defer func() {
		c.service.recordMetrics(c.ctx, route, now, metrics)
		c.service.recordLogs(c.ctx, route, now, payload.RequestContext, c.caller, metrics, logs)
	}()
	if err != nil {
		metrics.executionError = true
		rejected := failure("InternalServerErrorException", "Internal server error", http.StatusInternalServerError)
		var wire *awswire.Error
		if errors.As(err, &wire) {
			rejected = wire
			metrics.responseStatus(rejected.StatusCode)
		}
		logs.failure(rejected, "API_CONFIGURATION_ERROR")
		c.gatewayError("Internal server error", payload.RequestContext.RequestID, nil)
		return
	}
	if route.ResourceID == "" && route.FunctionARN == "" {
		metrics.clientError = true
		logs.failure(forbidden(), "ACCESS_DENIED")
		c.gatewayError("Forbidden", payload.RequestContext.RequestID, nil)
		return
	}
	metrics.messages = 1
	if route.FunctionARN == "" {
		metrics.executionError = true
		logs.failure(failure("InternalServerErrorException", "Internal server error", http.StatusInternalServerError), "API_CONFIGURATION_ERROR")
		c.gatewayError("Internal server error", payload.RequestContext.RequestID, &metrics)
		return
	}
	result, rejected := c.service.invoke(c.ctx, route, payload, c.caller, &metrics, &logs)
	if rejected != nil {
		c.gatewayError(rejected.Message, payload.RequestContext.RequestID, &metrics)
		return
	}
	if route.WebSocketResponseEnabled {
		if len(result.Body) > maxMessageSize {
			metrics.executionError = true
			logs.failure(payloadTooLarge(), "REQUEST_TOO_LARGE")
			c.terminate(c.service.ctx, 1009, "Message too big", true)
			return
		}
		if err := c.sendText(c.ctx, []byte(result.Body), &metrics); err != nil {
			logs.failure(gone(), "DEFAULT_5XX")
			c.terminate(context.Background(), 1006, "Connection closed abnormally", false)
		}
	}
}

func (c *connection) gatewayError(message, requestID string, metrics *eventMetrics) {
	body, _ := json.Marshal(map[string]string{"message": message, "connectionId": c.id, "requestId": requestID})
	if err := c.sendText(c.ctx, body, metrics); err != nil {
		c.terminate(context.Background(), 1006, "Connection closed abnormally", false)
	}
}

func (c *connection) disconnect() {
	if c.service.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(c.service.ctx, integrationTimeout)
	defer cancel()
	c.stateMu.Lock()
	now, code, reason := c.closedAt, c.closeCode, c.closeReason
	c.stateMu.Unlock()
	route, err := c.service.resolver.ResolveWebSocket(ctx, c.endpoint.api, c.endpoint.stage, "$disconnect", nil)
	if err != nil || route == nil || owner(route) != c.endpoint {
		return
	}
	payload := c.disconnectEvent(route, code, reason, now)
	logs := c.service.newEventLog(route, payload.RequestContext)
	metrics := eventMetrics{messages: 1}
	defer func() {
		c.service.recordMetrics(ctx, route, now, metrics)
		c.service.recordLogs(ctx, route, now, payload.RequestContext, c.caller, metrics, logs)
	}()
	if route.FunctionARN == "" {
		return
	}
	_, _ = c.service.invoke(ctx, route, payload, c.caller, &metrics, &logs)
}
