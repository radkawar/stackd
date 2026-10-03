package apigatewaywebsocket

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"stackd/iam/policy"
	"stackd/internal/services/apigatewayexec"
)

// The REQUEST authorizer has handshake maps but no integration body/base64 fields.
type authorizerRequest struct {
	Type                            string              `json:"type"`
	MethodARN                       string              `json:"methodArn"`
	Headers                         map[string]string   `json:"headers"`
	MultiValueHeaders               map[string][]string `json:"multiValueHeaders"`
	QueryStringParameters           map[string]string   `json:"queryStringParameters"`
	MultiValueQueryStringParameters map[string][]string `json:"multiValueQueryStringParameters"`
	StageVariables                  map[string]string   `json:"stageVariables"`
	RequestContext                  eventContext        `json:"requestContext"`
}

func (c *eventContext) authorizerIdentity(name string) (string, bool) {
	switch name {
	case "connectionId":
		return c.ConnectionID, true
	case "connectedAt":
		return strconv.FormatInt(c.ConnectedAt, 10), true
	case "requestTimeEpoch":
		return strconv.FormatInt(c.RequestTimeEpoch, 10), true
	default:
		// Native eventType/messageDirection sources fail identity admission,
		// despite those fields being present in the Lambda REQUEST event.
		return "", false
	}
}

func (c *connection) authorize(w http.ResponseWriter, r *http.Request, route *apigatewayexec.Route, connect *event, logs *eventLog) bool {
	requestID := connect.RequestContext.RequestID
	if len(r.Header.Values("Authorization")) > 1 {
		logs.failure(failure("BadRequestException", "Multiple Authorization headers", http.StatusBadRequest), "BAD_REQUEST_PARAMETERS")
		w.Header().Del("X-Amzn-Requestid")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n</body>\r\n</html>\r\n"))
		return false
	}
	if _, present := apigatewayexec.AuthorizerIdentities(r, route, "", false, connect.RequestContext.authorizerIdentity); !present {
		logs.failure(failure("UnauthorizedException", "Unauthorized", http.StatusUnauthorized), "UNAUTHORIZED")
		c.rejectConnect(w, requestID, http.StatusUnauthorized, "Unauthorized")
		return false
	}
	// WebSocket REQUEST authorizers retain IdentityValidationExpression but do
	// not apply it to the identity; native matching and nonmatching values invoke.
	headers := http.Header(connect.MultiValueHeaders).Clone()
	headers["Connection"] = []string{"upgrade"}
	headers["Upgrade"] = []string{"websocket"}
	if values := r.Header.Values("Sec-WebSocket-Extensions"); len(values) != 0 {
		headers["Sec-WebSocket-Extensions"] = values
	}
	headers.Del("Content-Length")
	headers["content-length"] = []string{"0"}
	// TODO: Comeback preserve arbitrary incoming header spelling at the owned
	// transport boundary; net/http has already canonicalized it in Request.Header.
	request := authorizerRequest{
		Type: "REQUEST", MethodARN: c.endpoint.arn("$connect"),
		Headers: lastValues(headers), MultiValueHeaders: headers,
		QueryStringParameters:           connect.QueryStringParameters,
		MultiValueQueryStringParameters: connect.MultiValueQueryStringParameters,
		StageVariables:                  route.StageVariables, RequestContext: connect.RequestContext,
	}
	if request.QueryStringParameters == nil {
		request.QueryStringParameters = map[string]string{}
	}
	if request.MultiValueQueryStringParameters == nil {
		request.MultiValueQueryStringParameters = map[string][]string{}
	}
	if request.StageVariables == nil {
		request.StageVariables = map[string]string{}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		logs.failure(failure("InternalServerErrorException", "Internal server error", http.StatusInternalServerError), "AUTHORIZER_FAILURE")
		c.rejectConnect(w, requestID, http.StatusInternalServerError, "Internal server error")
		return false
	}
	result, document, latency, err := c.service.authorizers.Invoke(r.Context(), route, payload, false)
	if err != nil {
		status, message := http.StatusInternalServerError, "Internal server error"
		switch {
		case errors.Is(err, apigatewayexec.ErrAuthorizerUnauthorized):
			status, message = http.StatusUnauthorized, "Unauthorized"
		case errors.Is(err, apigatewayexec.ErrAuthorizerResponse):
			message = ""
		}
		responseType := "AUTHORIZER_FAILURE"
		if status == http.StatusUnauthorized {
			responseType = "UNAUTHORIZED"
		}
		logs.failure(failure("AuthorizerException", message, status), responseType)
		c.rejectConnect(w, requestID, status, message)
		return false
	}
	decision, err := apigatewayexec.EvaluateAuthorizerPolicy(document, c.endpoint.arn("$connect"), r, c.service.clock.Now())
	if err != nil {
		logs.failure(failure("InternalServerErrorException", "", http.StatusInternalServerError), "AUTHORIZER_CONFIGURATION_ERROR")
		c.rejectConnect(w, requestID, http.StatusInternalServerError, "")
		return false
	}
	if decision != policy.Allow {
		message := "User is not authorized to access this resource because no identity-based policy allows the execute-api:Invoke action"
		if decision == policy.ExplicitDeny {
			message = "User is not authorized to access this resource with an explicit deny in an identity-based policy"
		}
		logs.failure(failure("ForbiddenException", message, http.StatusForbidden), "ACCESS_DENIED")
		c.rejectConnect(w, requestID, http.StatusForbidden, message)
		return false
	}
	c.authorizer = make(map[string]json.RawMessage, len(result.Context)+1)
	for name, raw := range result.Context {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			value = string(raw)
		}
		c.authorizer[name], _ = json.Marshal(value)
	}
	if result.PrincipalID != nil {
		c.authorizer["principalId"], _ = json.Marshal(*result.PrincipalID)
	}
	// Latency belongs to this CONNECT invocation, not the retained connection.
	connect.RequestContext.Authorizer = make(map[string]json.RawMessage, len(c.authorizer)+1)
	for name, value := range c.authorizer {
		connect.RequestContext.Authorizer[name] = value
	}
	connect.RequestContext.Authorizer["integrationLatency"] = json.RawMessage(strconv.FormatInt(latency, 10))
	return true
}
