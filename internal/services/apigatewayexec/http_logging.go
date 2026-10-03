package apigatewayexec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
)

type requestObservationKey struct{}

// requestObservation is created once at ingress, before authentication or Lambda
// invocation. Both integration/authorizer payloads use these same IDs and time.
type requestObservation struct {
	at                                                     time.Time
	requestID, extendedRequestID                           string
	errorMessage, responseType                             string
	integrationRequestID, integrationError, executionError string
	integrationStatus, backendStatus                       int
	authorizerError                                        string
	rest, info, dataTrace                                  bool
	executionLogs                                          []string
}

func newRequestObservation(r *http.Request, at time.Time, rest bool) *requestObservation {
	id := uuid.New()
	extended := base64.URLEncoding.EncodeToString(id[:11])
	requestID := extended
	if rest {
		requestID = uuid.NewString()
		if provided := r.Header.Get("x-amzn-RequestId"); provided != "" {
			if _, err := uuid.Parse(provided); err == nil {
				requestID = provided
			} else {
				requestID += "_REPLACED_INVALID_REQUEST_ID"
			}
		}
	}
	return &requestObservation{at: at, requestID: requestID, extendedRequestID: extended, rest: rest}
}

func requestObservationFrom(r *http.Request) *requestObservation {
	observation, _ := r.Context().Value(requestObservationKey{}).(*requestObservation)
	return observation
}

func (w *requestMetrics) recordRejection(rejected *rejection) {
	o := w.observation
	if o == nil {
		return
	}
	o.errorMessage = rejected.Message
	if o.responseType != "" {
		return
	}
	switch w.Header().Get("X-Amzn-ErrorType") {
	case "MissingAuthenticationTokenException":
		o.responseType = "MISSING_AUTHENTICATION_TOKEN"
	case "InvalidKeyParameter":
		o.responseType = "INVALID_API_KEY"
	case "QuotaExceededException":
		o.responseType = "QUOTA_EXCEEDED"
	case "TooManyRequestsException":
		o.responseType = "THROTTLED"
	}
	if o.responseType != "" {
		return
	}
	switch rejected.Status {
	case http.StatusUnauthorized:
		o.responseType = "UNAUTHORIZED"
	case http.StatusForbidden:
		o.responseType = "ACCESS_DENIED"
	case http.StatusRequestEntityTooLarge:
		o.responseType = "REQUEST_TOO_LARGE"
	case http.StatusTooManyRequests:
		o.responseType = "THROTTLED"
	case http.StatusGatewayTimeout:
		o.responseType = "INTEGRATION_TIMEOUT"
	default:
		if rejected.Status >= 500 {
			o.responseType = "DEFAULT_5XX"
		} else {
			o.responseType = "DEFAULT_4XX"
		}
	}
}

func (s *Handler) recordRequestLogs(r *http.Request, route *Route, path string, elapsed time.Duration, response *requestMetrics, identity requestIdentity) {
	if s.logs == nil {
		return
	}
	o := response.observation
	var access string
	if route.Logging.Access.DestinationARN != "" && route.Logging.Access.Format != "" {
		access = RenderAccessLog(route.Logging.Access.Format, requestLogValues(r, route, path, elapsed, response, identity))
	}
	if route.ProtocolType == "REST" && (route.Logging.Level == "INFO" || route.Logging.Level == "ERROR") {
		if o.dataTrace {
			o.execution("Method response body after transformations: " + string(response.responseBody))
			o.execution("Method response headers: " + executionParameters(response.Header()))
		}
		if o.errorMessage != "" {
			message := o.executionError
			if message == "" {
				message = o.integrationError
			}
			if message == "" {
				message = o.errorMessage
			}
			o.execution(message)
		} else if o.info {
			o.execution("Successfully completed execution")
		}
		if o.info || o.errorMessage != "" {
			o.execution("Method completed with status: " + strconv.Itoa(response.status))
			if o.integrationRequestID != "" {
				o.execution("AWS Integration Endpoint RequestId : " + o.integrationRequestID)
			}
		}
	}
	if access == "" && len(o.executionLogs) == 0 {
		return
	}
	if err := s.logs.PublishLogs(context.WithoutCancel(r.Context()), route, o.at, access, o.executionLogs); err != nil {
		slog.Warn("API Gateway log delivery failed", "api", route.APIID, "stage", route.Stage, "request_id", o.requestID, "error", err)
	}
}

func requestLogValues(r *http.Request, route *Route, path string, elapsed time.Duration, response *requestMetrics, identity requestIdentity) map[string]string {
	o := response.observation
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = r.RemoteAddr
	}
	domainPrefix, _, _ := strings.Cut(r.Host, ".")
	epoch := o.at.UnixMilli()
	if route.ProtocolType == "HTTP" {
		// Native HTTP access logs use seconds, unlike their Lambda payload and
		// REST access logs, which use milliseconds.
		epoch = o.at.Unix()
	}
	values := map[string]string{
		"requestId": o.requestID, "extendedRequestId": o.extendedRequestID,
		"accountId": route.AccountID, "apiId": route.APIID, "stage": route.Stage,
		"domainName": r.Host, "domainPrefix": domainPrefix,
		"httpMethod": r.Method, "path": path, "protocol": "HTTP/1.1",
		"requestTime": o.at.UTC().Format("02/Jan/2006:15:04:05 -0700"), "requestTimeEpoch": strconv.FormatInt(epoch, 10),
		"status": strconv.Itoa(response.status), "responseLength": strconv.FormatInt(response.responseBytes, 10),
		"responseLatency":   strconv.FormatInt(elapsed.Milliseconds(), 10),
		"identity.sourceIp": sourceIP, "identity.userAgent": r.UserAgent(),
		"error.message": o.errorMessage, "error.responseType": o.responseType, "authorizer.error": o.authorizerError,
		"integration.requestId": o.integrationRequestID, "awsEndpointRequestId": o.integrationRequestID,
		"integration.error": o.integrationError, "integrationErrorMessage": o.integrationError,
	}
	message := o.errorMessage
	if message == "" {
		message = "-"
	}
	quoted, _ := json.Marshal(message)
	values["error.messageString"] = string(quoted)
	if route.ProtocolType == "REST" {
		values["resourcePath"], values["resourceId"] = route.ResourcePath, route.ResourceID
		values["identity.apiKey"], values["identity.apiKeyId"] = identity.APIKey.Value, identity.APIKey.ID
	} else {
		values["routeKey"] = route.RouteKey
	}
	if response.integrated {
		latency := strconv.FormatInt(response.integrationLatency.Milliseconds(), 10)
		values["integration.latency"], values["integrationLatency"] = latency, latency
	}
	if o.integrationStatus != 0 {
		status := strconv.Itoa(o.integrationStatus)
		values["integration.integrationStatus"], values["integrationStatus"] = status, status
	}
	if o.backendStatus != 0 {
		values["integration.status"] = strconv.Itoa(o.backendStatus)
	}
	// TODO: Comeback calibrate HTTP dataProcessed for nonempty bodies and
	// pre-integration rejection. Only the measured empty-request Lambda payload
	// byte count is exposed; no invented internal envelope or zero fallback.
	if route.ProtocolType == "HTTP" && response.receivedPayload && response.requestBytes == 0 {
		values["dataProcessed"] = strconv.FormatInt(response.processedBytes, 10)
	}
	metadata := awsctx.FromContext(r.Context())
	if route.AuthorizationType == "AWS_IAM" && metadata.PrincipalARN != "" {
		values["identity.accountId"] = metadata.AccountID
		values["identity.caller"], values["identity.user"] = metadata.PrincipalID, metadata.PrincipalID
		values["identity.userArn"], values["identity.accessKey"] = metadata.PrincipalARN, metadata.AccessKeyID
	}
	for key, value := range projectedClaims(identity.Claims, route.ProtocolType == "REST") {
		values["authorizer.claims."+key] = value
	}
	if identity.Lambda != nil {
		if identity.Lambda.PrincipalID != nil {
			values["authorizer.principalId"] = *identity.Lambda.PrincipalID
		}
		values["authorizer.integrationLatency"] = strconv.FormatInt(identity.LambdaLatency, 10)
		for key, raw := range identity.Lambda.Context {
			var text string
			if json.Unmarshal(raw, &text) != nil {
				text = string(raw)
			}
			values["authorizer."+key] = text
		}
	}
	// TODO: Comeback expose authorizer invocation IDs/timings and federated
	// Cognito/organization, custom-domain and mTLS fields from their real owners.
	// Until then absent observations render '-' rather than synthesized context.
	return values
}
