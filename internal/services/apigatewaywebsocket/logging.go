package apigatewaywebsocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

// eventLog is request-local. It never outlives the worker processing the event.
// The resolved route supplies live stage settings, including on held sockets.
type eventLog struct {
	status                       int
	message, responseType        string
	requestID, endpointRequestID string
	info, errors, dataTrace      bool
	execution                    []string
}

func (s *Service) newEventLog(route *apigatewayexec.Route, request eventContext) eventLog {
	out := eventLog{status: http.StatusOK, requestID: request.RequestID}
	if s.logs == nil || route == nil {
		return out
	}
	out.info = route.Logging.Level == "INFO"
	out.errors = out.info || route.Logging.Level == "ERROR"
	out.dataTrace = out.info && route.Logging.DataTrace
	out.information("Extended Request Id: %s", request.ExtendedRequestID)
	out.information("Starting execution for request: %s", request.RequestID)
	out.information("WebSocket Request Route: [%s]", request.RouteKey)
	switch request.EventType {
	case "CONNECT":
		out.information("Client [UserAgent: %s, SourceIp: %s] is connecting to WebSocket API [%s].", request.Identity.UserAgent, request.Identity.SourceIP, request.APIID)
	case "MESSAGE":
		out.information("WebSocket API [%s] received message from client [Connection Id: %s].", request.APIID, request.ConnectionID)
	}
	return out
}

func (l *eventLog) information(format string, args ...any) {
	if l.info {
		l.execution = append(l.execution, apigatewayexec.FormatExecutionLog(l.requestID, fmt.Sprintf(format, args...)))
	}
}

func (l *eventLog) executionError(format string, args ...any) {
	if l.errors {
		l.execution = append(l.execution, apigatewayexec.FormatExecutionLog(l.requestID, fmt.Sprintf(format, args...)))
	}
}

func (l *eventLog) failure(rejected *awswire.Error, responseType string) {
	l.status = rejected.StatusCode
	l.message, l.responseType = rejected.Message, responseType
	l.executionError("Execution failed: %s", rejected.Message)
	if !l.info && l.endpointRequestID != "" {
		l.executionError("AWS Integration Endpoint RequestId : %s", l.endpointRequestID)
	}
}

func (s *Service) recordLogs(ctx context.Context, route *apigatewayexec.Route, at time.Time, request eventContext, caller awsctx.Metadata, metrics eventMetrics, record eventLog) {
	if s.logs == nil || route == nil {
		return
	}
	var access string
	if route.Logging.Access.DestinationARN != "" && route.Logging.Access.Format != "" {
		values := map[string]string{
			"requestId": request.RequestID, "extendedRequestId": request.ExtendedRequestID,
			"apiId": request.APIID, "stage": request.Stage, "routeKey": request.RouteKey,
			"status": strconv.Itoa(record.status), "eventType": request.EventType,
			"connectionId": request.ConnectionID, "messageId": request.MessageID,
			"domainName": request.DomainName, "requestTime": request.RequestTime,
			"requestTimeEpoch":  strconv.FormatInt(request.RequestTimeEpoch, 10),
			"identity.sourceIp": request.Identity.SourceIP, "identity.userAgent": request.Identity.UserAgent,
			"error.message": record.message, "error.responseType": record.responseType,
		}
		if request.EventType != "CONNECTION_API" && request.ConnectedAt != 0 {
			values["connectedAt"] = strconv.FormatInt(request.ConnectedAt, 10)
		}
		if metrics.integrationCalled || request.EventType == "CONNECTION_API" {
			values["integrationLatency"] = strconv.FormatInt(metrics.integrationLatency.Milliseconds(), 10)
		}
		// Native WebSocket rows leave the REST/HTTP integration.* aliases,
		// responseLength and responseLatency unset, even after invoking Lambda.
		if caller.PrincipalARN != "" {
			values["identity.caller"], values["identity.user"] = caller.PrincipalID, caller.PrincipalID
			values["identity.userArn"], values["identity.accountId"] = caller.PrincipalARN, caller.AccountID
		}
		if record.message != "" {
			values["error.messageString"] = strconv.Quote(record.message)
		}
		for name, raw := range request.Authorizer {
			var value string
			if json.Unmarshal(raw, &value) != nil {
				value = string(raw)
			}
			values["authorizer."+name] = value
		}
		access = apigatewayexec.RenderAccessLog(route.Logging.Access.Format, values)
	}
	if record.info {
		switch request.EventType {
		case "CONNECT":
			if record.status >= 200 && record.status < 300 {
				record.information("Client [Connection Id: %s] connected to API [%s] successfully.", request.ConnectionID, request.APIID)
			}
		case "MESSAGE":
			if metrics.integrationCalled {
				record.information("Message from client [Connection Id: %s] sent to API [%s] with response status code [%d].", request.ConnectionID, request.APIID, record.status)
			}
		case "DISCONNECT":
			if metrics.integrationCalled {
				record.information("Client [Connection Id: %s] disconnected from API [%s] with integration response status code [%d]. Close reason: [%d: %s]", request.ConnectionID, request.APIID, record.status, request.DisconnectStatusCode, request.DisconnectReason)
			} else {
				record.information("Client [Connection Id: %s] disconnected from API [%s]. Close reason: [%d: %s]", request.ConnectionID, request.APIID, request.DisconnectStatusCode, request.DisconnectReason)
			}
		case "CONNECTION_API":
			record.information("Connection API request completed with status: %d", record.status)
		}
	}
	if access == "" && len(record.execution) == 0 {
		return
	}
	// Delivery is best effort, but stays within the admitted worker lifetime.
	// A closed socket/request must not cancel its already-observed log records.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := s.logs.PublishLogs(ctx, route, at, access, record.execution); err != nil {
		slog.Error("API Gateway WebSocket log delivery failed", "api", route.APIID, "stage", route.Stage, "route", request.RouteKey, "error", err)
	}
}

type managementRequestContextKey struct{}

type managementRequest struct {
	at                time.Time
	domain            string
	identity          eventIdentity
	extendedRequestID string
}

func requestIdentity(r *http.Request) eventIdentity {
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = r.RemoteAddr
	}
	return eventIdentity{SourceIP: sourceIP, UserAgent: r.UserAgent()}
}

func (s *Service) managementLog(ctx context.Context, method, id string) (*apigatewayexec.Route, eventContext, eventLog) {
	if s.logs == nil && method != http.MethodPost {
		return nil, eventContext{}, eventLog{}
	}
	route := s.managementRoute(ctx, method)
	if route == nil {
		return nil, eventContext{}, eventLog{}
	}
	if s.logs == nil {
		return route, eventContext{}, eventLog{}
	}
	caller := awsctx.FromContext(ctx)
	transport, ok := ctx.Value(managementRequestContextKey{}).(managementRequest)
	if !ok {
		transport = managementRequest{at: s.clock.Now(), identity: eventIdentity{SourceIP: caller.SourceIP, UserAgent: caller.UserAgent}, extendedRequestID: caller.RequestID}
	}
	request := eventContext{RequestID: caller.RequestID, ExtendedRequestID: transport.extendedRequestID,
		RouteKey: method + " /@connections/{connectionId}", EventType: "CONNECTION_API",
		APIID: route.APIID, Stage: route.Stage, ConnectionID: id, DomainName: transport.domain,
		RequestTime: transport.at.UTC().Format("02/Jan/2006:15:04:05 -0700"), RequestTimeEpoch: transport.at.UnixMilli(), Identity: transport.identity}
	return route, request, s.newEventLog(route, request)
}

func (s *Service) recordManagementLogs(ctx context.Context, route *apigatewayexec.Route, request eventContext, record eventLog, rejected *awswire.Error) {
	if s.logs == nil || route == nil {
		return
	}
	if rejected != nil {
		// Native Gone responses have a status but no access-log error context.
		if rejected.StatusCode == http.StatusGone {
			record.status = rejected.StatusCode
			record.executionError("Connection API request failed: %s", rejected.Code)
		} else {
			record.failure(rejected, managementResponseType(rejected))
		}
	}
	s.recordLogs(ctx, route, time.UnixMilli(request.RequestTimeEpoch), request, awsctx.FromContext(ctx), eventMetrics{}, record)
}

func managementResponseType(rejected *awswire.Error) string {
	switch rejected.Code {
	case "AccessDeniedException", "ForbiddenException":
		return "ACCESS_DENIED"
	case "MissingAuthenticationTokenException":
		return "MISSING_AUTHENTICATION_TOKEN"
	case "BadRequestException", "413":
		return "BAD_REQUEST_BODY"
	default:
		return "DEFAULT_5XX"
	}
}

// recordHTTPFailure covers admission failures before lifecycle/management
// dispatch. There is no connection or Lambda invocation to manufacture here.
func (s *Service) recordHTTPFailure(r *http.Request, route *apigatewayexec.Route, rejected *awswire.Error, management bool) {
	if s.logs == nil {
		return
	}
	if management {
		id := ""
		if _, suffix, ok := strings.Cut(r.URL.EscapedPath(), "/@connections/"); ok {
			id, _ = url.PathUnescape(suffix)
		}
		resolved, request, record := s.managementLog(r.Context(), r.Method, id)
		s.recordManagementLogs(r.Context(), resolved, request, record, rejected)
		return
	}
	if route == nil {
		return
	}
	transport, ok := r.Context().Value(managementRequestContextKey{}).(managementRequest)
	if !ok {
		transport = managementRequest{at: s.clock.Now(), domain: r.Host, identity: requestIdentity(r)}
	}
	caller := awsctx.FromContext(r.Context())
	request := eventContext{RequestID: caller.RequestID, ExtendedRequestID: caller.RequestID,
		RouteKey: "$connect", EventType: "CONNECT", APIID: route.APIID, Stage: route.Stage,
		DomainName: transport.domain, Identity: transport.identity,
		RequestTime: transport.at.UTC().Format("02/Jan/2006:15:04:05 -0700"), RequestTimeEpoch: transport.at.UnixMilli()}
	record := s.newEventLog(route, request)
	record.failure(rejected, managementResponseType(rejected))
	s.recordLogs(r.Context(), route, transport.at, request, caller, eventMetrics{}, record)
}
