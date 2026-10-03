package apigatewaywebsocket

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/awsapi"
	managementapi "stackd/internal/awsapi/apigatewaymanagementapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

type Handler struct {
	service        *Service
	authentication apigatewayexec.Authenticator
}

func NewHandler(s *Service, authentication apigatewayexec.Authenticator) *Handler {
	return &Handler{service: s, authentication: authentication}
}

// ServeExecution claims only URLs owned by a WebSocket API. In particular a
// literal HTTP/REST /@connections route is not a management API request.
func (h *Handler) ServeExecution(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, apigatewayexec.Prefix) || h.service.resolver == nil {
		return false
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), apigatewayexec.Prefix)
	apiID, path, _ := strings.Cut(path, "/")
	stage, path, _ := strings.Cut(path, "/")
	apiID, apiErr := url.PathUnescape(apiID)
	stage, stageErr := url.PathUnescape(stage)
	if apiErr != nil || stageErr != nil {
		return false
	}
	route, err := h.service.resolver.ResolveWebSocket(r.Context(), apiID, stage, "$connect", nil)
	if errors.Is(err, apigatewayexec.ErrUnknownAPI) {
		return false
	}
	requestID := uuid.NewString()
	w.Header().Set("X-Amzn-Requestid", requestID)
	if err != nil || route == nil {
		rejected := forbidden()
		var wire *awswire.Error
		if errors.As(err, &wire) && wire.StatusCode != http.StatusNotFound {
			rejected = wire
		}
		writeExecutionError(w, rejected)
		return true
	}
	if !h.service.begin() {
		writeExecutionError(w, unavailable())
		return true
	}
	defer h.service.workers.Done()
	ctx, cancel := h.service.operationContext(r.Context())
	defer cancel()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: route.Partition,
		AccountID: route.AccountID, Region: route.Region, RequestID: requestID})
	ctx = contextWithEndpoint(ctx, owner(route))
	management := strings.HasPrefix(path, "@connections/")
	extendedRequestID := requestID
	if management {
		extendedRequestID = uuid.NewString()
		w.Header().Set("X-Amz-Apigw-Id", extendedRequestID)
	}
	ctx = context.WithValue(ctx, managementRequestContextKey{}, managementRequest{
		at: h.service.clock.Now(), domain: r.Host, identity: requestIdentity(r), extendedRequestID: extendedRequestID})
	r = r.WithContext(ctx)
	if path != "" && !management {
		h.service.recordHTTPFailure(r, route, forbidden(), false)
		writeExecutionError(w, forbidden())
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageSize))
	if err != nil {
		h.service.recordHTTPFailure(r, route, payloadTooLarge(), management)
		writePayloadTooLarge(w)
		return true
	}
	// Never rewrite the signed URL, host, query or body to perform route binding.
	r.Body = io.NopCloser(bytes.NewReader(body))
	if management || route.AuthorizationType == "AWS_IAM" {
		if h.authentication == nil {
			h.service.recordHTTPFailure(r, route, unavailable(), management)
			writeExecutionError(w, unavailable())
			return true
		}
		verified, rejected := h.authentication.Authenticate(r, "execute-api", route.Region)
		if rejected != nil {
			failure := forbidden()
			if r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Credential") == "" {
				failure = &awswire.Error{Code: "MissingAuthenticationTokenException", Message: "Missing Authentication Token", StatusCode: http.StatusForbidden}
			}
			h.service.recordHTTPFailure(r, route, failure, management)
			writeExecutionError(w, failure)
			return true
		}
		r = verified
	}
	if management {
		h.serveManagement(w, r, owner(route), "/"+path, body)
	} else {
		h.service.connect(w, r, route)
	}
	return true
}

func (h *Handler) serveManagement(w http.ResponseWriter, r *http.Request, target endpoint, path string, body []byte) {
	model, _ := awscatalog.LookupService("apigatewaymanagementapi")
	op, labels, ok := model.MatchHTTPOperation(r.Method, path, r.URL.Query(), r.Header)
	if !ok {
		h.service.recordHTTPFailure(r, nil, forbidden(), true)
		awswire.RESTJSONError(w, r, &model, forbidden())
		return
	}
	decoded, err := managementapi.DecodeRequest(string(op.Name), awsapi.Request{
		Body: body, Header: r.Header, Host: r.Host, Query: r.URL.Query(), Labels: labels})
	if err != nil {
		rejected := h.service.RequestError(string(op.Name), err)
		h.service.recordHTTPFailure(r, nil, rejected, true)
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	ctx := contextWithEndpoint(r.Context(), target)
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	h.service.ServeHTTP(w, r.WithContext(ctx))
}

func writeExecutionError(w http.ResponseWriter, rejected *awswire.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-Errortype", rejected.Code)
	w.WriteHeader(rejected.StatusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": rejected.Message})
}

func (c *connection) rejectConnect(w http.ResponseWriter, requestID string, status int, message string) {
	w.Header().Del("X-Amzn-Requestid")
	w.Header().Del("X-Amzn-Errortype")
	w.Header().Set("X-Amz-Apigw-Id", requestID)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Message      string `json:"message"`
		ConnectionID string `json:"connectionId"`
		RequestID    string `json:"requestId"`
	}{message, c.id, requestID})
}
