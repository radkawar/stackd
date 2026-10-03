package apigatewaywebsocket

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
	"stackd/internal/services/apigatewayexec"
)

type eventIdentity struct {
	UserAgent string `json:"userAgent"`
	SourceIP  string `json:"sourceIp"`
}

type eventContext struct {
	RouteKey             string                     `json:"routeKey"`
	MessageID            string                     `json:"messageId,omitempty"`
	EventType            string                     `json:"eventType"`
	ExtendedRequestID    string                     `json:"extendedRequestId"`
	RequestTime          string                     `json:"requestTime"`
	MessageDirection     string                     `json:"messageDirection"`
	Stage                string                     `json:"stage"`
	ConnectedAt          int64                      `json:"connectedAt"`
	RequestTimeEpoch     int64                      `json:"requestTimeEpoch"`
	Identity             eventIdentity              `json:"identity"`
	RequestID            string                     `json:"requestId"`
	DomainName           string                     `json:"domainName"`
	ConnectionID         string                     `json:"connectionId"`
	APIID                string                     `json:"apiId"`
	DisconnectStatusCode int                        `json:"disconnectStatusCode,omitempty"`
	DisconnectReason     string                     `json:"disconnectReason,omitempty"`
	Authorizer           map[string]json.RawMessage `json:"authorizer,omitempty"`
}

type event struct {
	Headers                         map[string]string   `json:"headers,omitempty"`
	MultiValueHeaders               map[string][]string `json:"multiValueHeaders,omitempty"`
	QueryStringParameters           map[string]string   `json:"queryStringParameters,omitempty"`
	MultiValueQueryStringParameters map[string][]string `json:"multiValueQueryStringParameters,omitempty"`
	RequestContext                  eventContext        `json:"requestContext"`
	StageVariables                  map[string]string   `json:"stageVariables,omitempty"`
	Body                            *string             `json:"body,omitempty"`
	IsBase64Encoded                 bool                `json:"isBase64Encoded"`
}

func (c *connection) event(route *apigatewayexec.Route, kind string, now time.Time, requestID string) event {
	if requestID == "" {
		requestID = uuid.NewString()
	}
	return event{RequestContext: eventContext{
		RouteKey: route.RouteKey, EventType: kind, ExtendedRequestID: requestID,
		RequestTime: now.UTC().Format("02/Jan/2006:15:04:05 -0700"), MessageDirection: "IN",
		Stage: c.endpoint.stage, ConnectedAt: c.connectedAt.UnixMilli(), RequestTimeEpoch: now.UnixMilli(),
		Identity: c.identity, RequestID: requestID, DomainName: c.domain,
		ConnectionID: c.id, APIID: c.endpoint.api, Authorizer: c.authorizer,
	}, StageVariables: route.StageVariables}
}

func (c *connection) connectEvent(r *http.Request, route *apigatewayexec.Route, now time.Time) event {
	out := c.event(route, "CONNECT", now, awsctx.FromContext(r.Context()).RequestID)
	out.RequestContext.RouteKey = "$connect"
	headers := r.Header.Clone()
	headers.Del("Connection")
	headers.Del("Upgrade")
	headers.Del("Sec-WebSocket-Extensions")
	for _, key := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"} {
		if values, ok := headers[http.CanonicalHeaderKey(key)]; ok {
			headers.Del(key)
			headers[key] = values
		}
	}
	if headers.Get("X-Amzn-Trace-Id") == "" {
		headers.Set("X-Amzn-Trace-Id", "Root="+awsctx.NewTraceID(now))
	}
	headers.Set("Host", r.Host)
	headers.Set("X-Forwarded-For", c.identity.SourceIP)
	if r.TLS == nil {
		headers.Set("X-Forwarded-Proto", "http")
		headers.Set("X-Forwarded-Port", "80")
	} else {
		headers.Set("X-Forwarded-Proto", "https")
		headers.Set("X-Forwarded-Port", "443")
	}
	out.MultiValueHeaders = headers
	out.Headers = lastValues(headers)
	query := r.URL.Query()
	out.MultiValueQueryStringParameters = query
	out.QueryStringParameters = lastValues(query)
	return out
}

func (c *connection) messageEvent(route *apigatewayexec.Route, body []byte, now time.Time) event {
	out := c.event(route, "MESSAGE", now, "")
	out.RequestContext.MessageID = uuid.NewString()
	bodyText := string(body)
	out.Body = &bodyText
	return out
}

func (c *connection) disconnectEvent(route *apigatewayexec.Route, code int, reason string, now time.Time) event {
	out := c.event(route, "DISCONNECT", now, "")
	out.RequestContext.RouteKey = "$disconnect"
	out.RequestContext.DisconnectStatusCode, out.RequestContext.DisconnectReason = code, reason
	out.Headers = map[string]string{"Host": c.domain, "x-api-key": "", "X-Forwarded-For": "", "x-restapi": ""}
	out.MultiValueHeaders = make(map[string][]string, len(out.Headers))
	for name, value := range out.Headers {
		out.MultiValueHeaders[name] = []string{value}
	}
	return out
}

func lastValues(values map[string][]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		if len(value) != 0 {
			out[key] = value[len(value)-1]
		}
	}
	return out
}
