package apigatewaywebsocket

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigatewaymanagementapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

func contextWithEndpoint(ctx context.Context, target endpoint) context.Context {
	return context.WithValue(ctx, endpointContextKey{}, target)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("apigatewaymanagementapi")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerErrorException", "Missing generated request binding", 500))
		return
	}
	output, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		if rejected.StatusCode == http.StatusRequestEntityTooLarge {
			writePayloadTooLarge(w)
		} else {
			awswire.RESTJSONError(w, r, &model, rejected)
		}
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, output)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerErrorException", "Unable to encode management response", 500))
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func (s *Service) ExecuteCommand(ctx context.Context, in awsapi.DecodedRequest) (any, *awswire.Error) {
	if !s.begin() {
		return nil, unavailable()
	}
	defer s.workers.Done()
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	switch in.Operation.Name {
	case awscatalog.ApiGatewayManagementApiOpGetConnection:
		input, ok := in.Input.(*api.GetConnectionInput)
		if !ok || input == nil {
			return nil, invalidInput()
		}
		return s.getConnection(ctx, input)
	case awscatalog.ApiGatewayManagementApiOpPostToConnection:
		input, ok := in.Input.(*api.PostToConnectionInput)
		if !ok || input == nil {
			return nil, invalidInput()
		}
		return s.postToConnection(ctx, input)
	case awscatalog.ApiGatewayManagementApiOpDeleteConnection:
		input, ok := in.Input.(*api.DeleteConnectionInput)
		if !ok || input == nil {
			return nil, invalidInput()
		}
		return s.deleteConnection(ctx, input)
	default:
		return nil, failure("NotImplementedException", "Management operation is not supported", http.StatusNotImplemented)
	}
}

func invalidInput() *awswire.Error {
	return failure("BadRequestException", "Missing connectionId", http.StatusBadRequest)
}

func (s *Service) managementConnection(ctx context.Context, id, method string) (*connection, *awswire.Error) {
	target, ok := ctx.Value(endpointContextKey{}).(endpoint)
	if !ok {
		return nil, forbidden()
	}
	if id == "" {
		return nil, invalidInput()
	}
	// TODO: Comeback match native opaque connection-ID admission once its rule is
	// established; syntactic resemblance alone did not establish native validity.
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	caller := awsctx.FromContext(ctx)
	if caller.PrincipalARN == "" && caller.AccessKeyID == "" {
		return nil, forbidden()
	}
	// Native IAM evaluates the literal route template, NOT the actual
	// connection ID. The request endpoint's stage scopes authorization, while
	// a connection is addressable through every existing stage of its API.
	if rejected := s.authorization.Authorize(ctx, authorization.Request{
		Action:            "execute-api:ManageConnections",
		ResourceARN:       target.arn(method + "/@connections/{connectionId}"),
		ResourceAccountID: target.account,
	}); rejected != nil {
		if rejected.StatusCode == http.StatusForbidden || rejected.Code == "AccessDenied" {
			return nil, failure("AccessDeniedException", rejected.Message, http.StatusForbidden)
		}
		return nil, rejected
	}
	s.mu.Lock()
	c := s.connections[target.connectionKey(id)]
	s.mu.Unlock()
	if c == nil {
		return nil, gone()
	}
	c.stateMu.Lock()
	closed, lastActive := c.closed, c.lastActive
	c.stateMu.Unlock()
	if closed {
		return nil, gone()
	}
	now := s.clock.Now()
	if !now.Before(c.connectedAt.Add(maxLifetime)) {
		c.terminate(ctx, 1001, "Connection duration exceeded", true)
		return nil, gone()
	}
	if !now.Before(lastActive.Add(idleTimeout)) {
		c.terminate(ctx, 1001, "Idle timeout", true)
		return nil, gone()
	}
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	return c, nil
}

func (s *Service) getConnection(ctx context.Context, in *api.GetConnectionInput) (_ *api.GetConnectionOutput, rejected *awswire.Error) {
	route, request, logs := s.managementLog(ctx, http.MethodGet, text(in.ConnectionId))
	defer func() { s.recordManagementLogs(ctx, route, request, logs, rejected) }()
	c, rejected := s.managementConnection(ctx, text(in.ConnectionId), http.MethodGet)
	if rejected != nil {
		return nil, rejected
	}
	c.stateMu.Lock()
	connectedAt, lastActive, closed := c.connectedAt, c.lastActive, c.closed
	c.stateMu.Unlock()
	if closed {
		return nil, gone()
	}
	identity := &api.Identity{}
	setText(&identity.SourceIp, c.identity.SourceIP)
	setText(&identity.UserAgent, c.identity.UserAgent)
	out := &api.GetConnectionOutput{ConnectedAt: &connectedAt, LastActiveAt: &lastActive, Identity: identity}
	if logs.dataTrace {
		body, _ := json.Marshal(out)
		logs.information("Connection API response body: %s", body)
	}
	return out, nil
}

func (s *Service) postToConnection(ctx context.Context, in *api.PostToConnectionInput) (_ *api.PostToConnectionOutput, rejected *awswire.Error) {
	now := s.clock.Now()
	route, request, logs := s.managementLog(ctx, http.MethodPost, text(in.ConnectionId))
	defer func() { s.recordManagementLogs(ctx, route, request, logs, rejected) }()
	if logs.dataTrace {
		logs.information("Connection API request body: %s", apigatewayexec.RedactExecutionLogPayload(in.Data))
	}
	metrics := eventMetrics{}
	defer func() { s.recordPostMetrics(ctx, route, now, metrics, rejected) }()
	if len(in.Data) > maxMessageSize {
		return nil, payloadTooLarge()
	}
	c, rejected := s.managementConnection(ctx, text(in.ConnectionId), http.MethodPost)
	if rejected != nil {
		return nil, rejected
	}
	if err := c.sendText(ctx, in.Data, &metrics); err != nil {
		c.terminate(context.Background(), 1006, "Connection closed abnormally", false)
		if ctx.Err() != nil {
			return nil, unavailable()
		}
		return nil, gone()
	}
	return &api.PostToConnectionOutput{}, nil
}

func (s *Service) deleteConnection(ctx context.Context, in *api.DeleteConnectionInput) (_ *api.DeleteConnectionOutput, rejected *awswire.Error) {
	route, request, logs := s.managementLog(ctx, http.MethodDelete, text(in.ConnectionId))
	logs.status = http.StatusNoContent
	defer func() { s.recordManagementLogs(ctx, route, request, logs, rejected) }()
	c, rejected := s.managementConnection(ctx, text(in.ConnectionId), http.MethodDelete)
	if rejected != nil {
		return nil, rejected
	}
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	c.terminate(ctx, 1000, "Connection Closed Normally", true)
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	return &api.DeleteConnectionOutput{}, nil
}

func payloadTooLarge() *awswire.Error { return failure("413", "", http.StatusRequestEntityTooLarge) }

func writePayloadTooLarge(w http.ResponseWriter) {
	w.Header().Del("X-Amzn-Requestid")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
}

func (s *Service) RequestError(_ string, err error) *awswire.Error {
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && validation.Path == "Data" && validation.Constraint == "length.max" {
		return payloadTooLarge()
	}
	return failure("BadRequestException", err.Error(), http.StatusBadRequest)
}
