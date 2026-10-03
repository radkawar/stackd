package apigatewayexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const Prefix = "/_stackd/execute-api/"

type Authenticator interface {
	Authenticate(*http.Request, string, string) (*http.Request, *awswire.Error)
}

type Functions interface {
	Invoke(context.Context, *lambdaapi.InvokeInput) (*lambdaapi.InvokeOutput, string, *awswire.Error)
}

// InvocationRoles resolves current invocation authority outside service transactions.
type InvocationRoles interface {
	InvocationContext(context.Context, string, bool) (context.Context, *awswire.Error)
}

type Config struct {
	HTTP, REST     Resolver
	Authentication Authenticator
	Authorization  authorization.Authorizer
	Functions      Functions
	Roles          InvocationRoles
	Keys           KeySource
	UsagePlans     UsagePlans
	Metrics        Metrics
	Logs           LogPublisher
	Clock          clock.Clock
}

type Handler struct {
	http, rest         Resolver
	authentication     Authenticator
	authorization      authorization.Authorizer
	functions          Functions
	roles              InvocationRoles
	authorizers        *AuthorizerExecutor
	keys               KeySource
	usagePlans         UsagePlans
	metrics            Metrics
	logs               LogPublisher
	clock              clock.Clock
	validationPatterns sync.Map
}

func New(c Config) *Handler {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	return &Handler{http: c.HTTP, rest: c.REST, authentication: c.Authentication,
		authorization: c.Authorization, functions: c.Functions, roles: c.Roles, authorizers: NewAuthorizerExecutor(c.Functions, c.Roles), keys: c.Keys, usagePlans: c.UsagePlans, metrics: c.Metrics, logs: c.Logs, clock: c.Clock}
}

func (s *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started, at := time.Now(), s.clock.Now()
	path := strings.TrimPrefix(r.URL.Path, Prefix)
	apiID, path, _ := strings.Cut(path, "/")
	path = "/" + path
	var route *Route
	err := ErrUnknownAPI
	if s.http != nil {
		route, err = s.http.Resolve(r.Context(), apiID, "", r.Method, path)
	}
	rest := false
	if errors.Is(err, ErrUnknownAPI) && s.rest != nil {
		route, err = s.rest.Resolve(r.Context(), apiID, "", r.Method, path)
		rest = !errors.Is(err, ErrUnknownAPI)
	}
	observation := newRequestObservation(r, at, rest)
	r = r.WithContext(context.WithValue(r.Context(), requestObservationKey{}, observation))
	if rest {
		w.Header().Set("x-amzn-RequestId", observation.requestID)
		w.Header().Set("x-amz-apigw-id", observation.extendedRequestID)
	} else {
		w.Header().Set("apigw-requestid", observation.requestID)
	}
	response := &requestMetrics{ResponseWriter: w, observation: observation}
	var identity requestIdentity
	if route != nil {
		w = response
		selected := err == nil
		if selected && rest && s.logs != nil {
			observation.info = route.Logging.Level == "INFO"
			observation.dataTrace = observation.info && route.Logging.DataTrace
			if observation.info {
				observation.execution("Extended Request Id: " + observation.extendedRequestID)
			}
		}
		defer func() {
			elapsed := time.Since(started)
			s.recordRequestMetrics(r.Context(), route, at, elapsed, response)
			if selected {
				s.recordRequestLogs(r, route, path, elapsed, response, identity)
			}
		}()
	}
	if route == nil || err != nil {
		rejected := &rejection{http.StatusNotFound, "Not Found"}
		var wire *awswire.Error
		if errors.As(err, &wire) {
			rejected = &rejection{wire.StatusCode, wire.Message}
		} else if err != nil && !errors.Is(err, ErrUnknownAPI) {
			rejected = &rejection{http.StatusInternalServerError, "Internal Server Error"}
		}
		writeRejection(w, rejected)
		return
	}
	metadata := awsctx.Metadata{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region, RequestID: observation.requestID}
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
	response.requestBytes = int64(len(body))
	if err != nil {
		writeRejection(w, &rejection{http.StatusRequestEntityTooLarge, "Request Too Long"})
		return
	}
	// Authentication needs the original signed host/path/query and complete body.
	r.Body = io.NopCloser(bytes.NewReader(body))
	switch route.AuthorizationType {
	case "NONE", "":
	case "AWS_IAM":
		verified, authorized := s.authorizeIAM(w, r, route, path, rest)
		if verified != nil {
			r = verified
		}
		if !authorized {
			return
		}
	case "JWT", "COGNITO_USER_POOLS":
		var rejected *rejection
		identity, rejected = s.authorizeToken(r, route, rest)
		if rejected != nil {
			writeRejection(w, rejected)
			return
		}
	case "CUSTOM":
		var rejected *rejection
		identity, rejected = s.authorizeLambda(r, route, path, rest)
		if rejected != nil {
			if rejected.Status >= 500 {
				observation.responseType = "AUTHORIZER_FAILURE"
			}
			writeAuthorizerRejection(w, rejected, rest)
			return
		}
	default:
		writeRejection(w, &rejection{http.StatusInternalServerError, "Internal Server Error"})
		return
	}
	if !s.admitUsage(w, r, route, &identity, rest) {
		return
	}
	if observation.info {
		observation.execution("Starting execution for request: " + observation.requestID)
		observation.execution("HTTP Method: " + r.Method + ", Resource Path: " + route.ResourcePath)
	}
	if observation.dataTrace {
		observation.traceRequest(r, route, body)
	}
	payload, err := json.Marshal(s.payload(r, route, path, body, identity, rest))
	if err != nil || s.functions == nil {
		writeRejection(w, &rejection{http.StatusInternalServerError, "Internal Server Error"})
		return
	}
	caller := awsctx.FromContext(r.Context())
	metadata.ParentEventID, metadata.TraceHeader = caller.ParentEventID, caller.TraceHeader
	metadata.ServicePrincipal = awsctx.ServicePrincipal{Name: "apigateway.amazonaws.com", SourceARN: executionARN(route, r.Method, executionPath(route, path)), Type: "Service"}
	metadata.InvokedBy = "apigateway.amazonaws.com"
	ctx := awsctx.WithMetadata(r.Context(), metadata)
	timeout := 30 * time.Second
	if rest {
		timeout = 29 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var roleFailure *awswire.Error
	ctx, roleFailure = IntegrationContext(ctx, route.IntegrationCredentialsARN, s.roles, caller, rest)
	if roleFailure != nil {
		observation.responseType = "API_CONFIGURATION_ERROR"
		observation.integrationError = roleFailure.Message
		writeIntegrationFailure(w, rest)
		return
	}
	if observation.dataTrace {
		observation.executionData("Endpoint request body after transformations: ", RedactExecutionLogPayload(payload))
	}
	name := lambdaapi.NamespacedFunctionName(route.FunctionARN)
	integrationStarted := time.Now()
	output, invocationID, rejected := s.functions.Invoke(ctx, &lambdaapi.InvokeInput{FunctionName: &name, Payload: lambdaapi.Blob(payload)})
	observation.integrationRequestID = invocationID
	response.integrated = true
	response.integrationLatency = time.Since(integrationStarted)
	if output != nil {
		response.receivedPayload = true
		response.processedBytes = response.requestBytes + int64(len(output.Payload))
		if output.StatusCode != nil {
			observation.integrationStatus = int(*output.StatusCode)
		}
		if observation.dataTrace {
			observation.execution("Received response. Status: " + strconv.Itoa(observation.integrationStatus) + ", Integration latency: " + strconv.FormatInt(response.integrationLatency.Milliseconds(), 10) + " ms")
			observation.executionData("Endpoint response body before transformations: ", RedactExecutionLogPayload(output.Payload))
		}
	}
	if ctx.Err() != nil {
		observation.integrationError = "Endpoint request timed out"
		writeRejection(w, &rejection{http.StatusGatewayTimeout, "Endpoint request timed out"})
		return
	}
	if rejected != nil {
		observation.responseType = "INTEGRATION_FAILURE"
		observation.integrationStatus = rejected.StatusCode
		observation.integrationError = rejected.Message
		writeIntegrationFailure(w, rest)
		return
	}
	if output == nil {
		observation.responseType = "INTEGRATION_FAILURE"
		observation.integrationError = "Lambda invocation returned no response"
		writeIntegrationFailure(w, rest)
		return
	}
	if output.FunctionError != nil {
		var failure struct {
			ErrorMessage string `json:"errorMessage"`
		}
		_ = json.Unmarshal(output.Payload, &failure)
		observation.responseType = "INTEGRATION_FAILURE"
		status, message := http.StatusInternalServerError, "Internal Server Error"
		observation.backendStatus = status
		observation.integrationError = "The Lambda function returned the following error: " + failure.ErrorMessage + ". Check your Lambda function code and try again."
		if rest {
			status, message = http.StatusBadGateway, "Internal server error"
			observation.backendStatus = 0
			observation.integrationError = "Lambda Customer Function Error:" + failure.ErrorMessage
			observation.executionError = "Lambda execution failed with status " + strconv.Itoa(observation.integrationStatus) + " due to customer function error: " + failure.ErrorMessage + ". Lambda request id: " + invocationID
		}
		writeRejection(w, &rejection{status, message})
		return
	}
	observation.responseType = "INTEGRATION_FAILURE"
	if writeProxyResponse(w, output.Payload, route.PayloadVersion == "2.0") {
		observation.responseType = ""
		observation.backendStatus = response.status
	} else {
		observation.integrationError = "Malformed Lambda proxy response"
	}
}

func (s *Handler) admitUsage(w http.ResponseWriter, r *http.Request, route *Route, identity *requestIdentity, rest bool) bool {
	if !rest {
		return true
	}
	var key string
	switch route.APIKeySource {
	case "", "HEADER":
		key = r.Header.Get("x-api-key")
	case "AUTHORIZER":
		if !route.APIKeyRequired {
			// TODO: Comeback capture optional CUSTOM methods that return a
			// usageIdentifierKey; current evidence covers optional NONE only.
			return true
		}
		if identity.Lambda != nil {
			key = identity.Lambda.UsageIdentifierKey
		}
	default:
		writeIntegrationFailure(w, true)
		return false
	}
	observation := requestObservationFrom(r)
	loggedKey := ""
	if key != "" {
		loggedKey = "[REDACTED]"
	}
	if observation.info {
		observation.execution("Verifying Usage Plan for request: " + observation.requestID + ". API Key: " + loggedKey + " API Stage: " + route.APIID + "/" + route.Stage)
	}
	if !route.APIKeyRequired && key == "" {
		if observation.info {
			observation.execution("API Key  authorized because method '" + r.Method + " " + route.ResourcePath + "' does not require API Key. Request will not contribute to throttle or quota limits")
			observation.execution("Usage Plan check succeeded for API Key  and API Stage " + route.APIID + "/" + route.Stage)
		}
		return true
	}
	if s.usagePlans == nil {
		writeIntegrationFailure(w, true)
		return false
	}
	admitted, err := s.usagePlans.AdmitUsage(r.Context(), route, key)
	if err != nil {
		var rejected *awswire.Error
		if errors.As(err, &rejected) {
			w.Header().Set("X-Amzn-ErrorType", rejected.Code)
			writeRejection(w, &rejection{rejected.StatusCode, rejected.Message})
		} else {
			writeIntegrationFailure(w, true)
		}
		return false
	}
	identity.APIKey = admitted
	if observation.info {
		observation.execution("Usage Plan check succeeded for API Key " + loggedKey + " and API Stage " + route.APIID + "/" + route.Stage)
	}
	return true
}

func executionPath(route *Route, path string) string {
	if route.Stage != "$default" {
		return strings.TrimPrefix(path, "/"+route.Stage)
	}
	return path
}

func executionARN(route *Route, method, path string) string {
	return "arn:" + route.Partition + ":execute-api:" + route.Region + ":" + route.AccountID + ":" + route.APIID + "/" + route.Stage + "/" + method + "/" + strings.TrimPrefix(path, "/")
}

func writeRejection(w http.ResponseWriter, rejected *rejection) {
	if recorder, ok := w.(interface{ recordRejection(*rejection) }); ok {
		recorder.recordRejection(rejected)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rejected.Status)
	_ = json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{rejected.Message})
}

func writeIntegrationFailure(w http.ResponseWriter, rest bool) {
	message := "Internal Server Error"
	if rest {
		w.Header().Set("X-Amzn-ErrorType", "InternalServerErrorException")
		message = "Internal server error"
	}
	writeRejection(w, &rejection{http.StatusInternalServerError, message})
}
