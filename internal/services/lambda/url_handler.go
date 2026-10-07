package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/iam/policy"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/endpoints"
	"stackd/internal/gateway"
)

// FunctionURLAuthenticator verifies the original HTTP target before its private
// routing prefix is removed from the customer event.
type FunctionURLAuthenticator interface {
	Authenticate(*http.Request, string, string) (*http.Request, *awswire.Error)
}

// FunctionURLHandler connects public HTTP requests to Lambda's owned admission
// and execution path. Authentication, IAM activity and organization membership
// retain their existing authorities rather than a second URL identity store.
type FunctionURLHandler struct {
	service       *Service
	authenticator FunctionURLAuthenticator
	activity      gateway.ActivityRecorder
	organizations authorization.OrganizationSource
}

func NewFunctionURLHandler(service *Service, authenticator FunctionURLAuthenticator, activity gateway.ActivityRecorder, organizations authorization.OrganizationSource) *FunctionURLHandler {
	return &FunctionURLHandler{service: service, authenticator: authenticator, activity: activity, organizations: organizations}
}

// ServeFunctionURL reports whether this public route owns the request.
func (h *FunctionURLHandler) ServeFunctionURL(w http.ResponseWriter, r *http.Request) bool {
	if id, region, matched := endpoints.ResourceHost(r.Host, h.service.endpointDomain, "lambda-url"); matched {
		if id == "" || region == "" {
			writeFunctionURLJSONFailure(w, http.StatusForbidden, nil)
			return true
		}
		h.serve(w, r, id, r.URL.EscapedPath(), region)
		return true
	}
	path, matched := strings.CutPrefix(r.URL.EscapedPath(), functionURLPrefix)
	if !matched {
		return false
	}
	id, customerPath, _ := strings.Cut(path, "/")
	h.serve(w, r, id, "/"+customerPath, "")
	return true
}

func (h *FunctionURLHandler) serve(w http.ResponseWriter, r *http.Request, id, customerPath, region string) {
	s := h.service
	requestID := uuid.NewString()
	w.Header().Set("X-Amzn-Requestid", requestID)
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{RequestID: requestID}))
	var record FunctionURLRecord
	err := s.repository.View(r.Context(), func(reader Reader) error {
		var err error
		record, err = reader.FunctionURLByID(id)
		if err == nil && region != "" && record.Key.Region != region {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeFunctionURLJSONFailure(w, http.StatusForbidden, nil)
		} else {
			writeFunctionURLFailure(w, http.StatusInternalServerError)
		}
		return
	}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		writeFunctionURLFailure(w, http.StatusServiceUnavailable)
		return
	}
	s.work.Add(1)
	s.mu.Unlock()
	defer s.work.Done()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	// A disconnected receiver or shutdown releases blocked writes and empty
	// streaming responses, without canceling accepted customer execution.
	interrupt := context.AfterFunc(ctx, func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()) })
	defer interrupt()
	response := &functionURLResponseWriter{ResponseWriter: w}
	started, at := time.Now(), s.clock.Now()
	var executedVersion string
	var functionError bool
	defer func() {
		if err := s.recordFunctionURLMetrics(context.WithoutCancel(r.Context()), record.Key, at, time.Since(started), response.status, executedVersion, functionError); err != nil {
			slog.Error("Lambda URL metric commit failed", "function", record.Key.ARN(), "request", requestID, "error", err)
		}
	}()
	settings := record.EffectiveSettings(at)
	if functionURLPreflight(response, r, settings.Cors) {
		return
	}
	metadata := awsctx.Metadata{RequestID: requestID, AccountID: policy.AnonymousAccountID, Partition: record.Key.Partition, Region: record.Key.Region}
	gateway.BindRequestTransport(r, &metadata)
	r = r.WithContext(awsctx.WithMetadata(ctx, metadata))
	r.Body = http.MaxBytesReader(response, r.Body, 6<<20)
	if settings.AuthType == "AWS_IAM" {
		authenticated, wire := h.authenticator.Authenticate(r, "lambda", record.Key.Region)
		if wire != nil {
			status := http.StatusForbidden
			if wire.StatusCode == http.StatusRequestEntityTooLarge {
				status = wire.StatusCode
			}
			writeFunctionURLJSONFailure(response, status, new(http.StatusText(status)))
			return
		}
		r = authenticated
		if err := h.activity.RecordActivity(r.Context(), "lambda", "InvokeFunctionUrl"); err != nil {
			writeFunctionURLFailure(response, http.StatusInternalServerError)
			return
		}
	}
	principalOrgID := ""
	if settings.AuthType == "AWS_IAM" {
		var err error
		principalOrgID, _, err = h.organizations.PrincipalOrganization(r.Context())
		if err != nil {
			writeFunctionURLFailure(response, http.StatusInternalServerError)
			return
		}
	}
	decodedPath, err := url.PathUnescape(customerPath)
	if err != nil {
		writeFunctionURLFailure(response, http.StatusBadRequest)
		return
	}
	customerURL := *r.URL
	customerURL.Path, customerURL.RawPath = decodedPath, customerPath
	r.URL = &customerURL
	request, wire := decodeFunctionURLRequest(r, record.ID, at, principalOrgID)
	if wire != nil {
		writeFunctionURLFailure(response, wire.StatusCode)
		return
	}
	if s.apiEvents != nil {
		ctx, err := apievents.Reserve(r.Context())
		if err != nil {
			writeFunctionURLFailure(response, http.StatusInternalServerError)
			return
		}
		r = r.WithContext(ctx)
	}
	input := &api.InvokeInput{FunctionName: new(api.NamespacedFunctionName(record.Key.ARN())), Payload: request.Payload}
	options := invocationOptions{URLAuthType: settings.AuthType, TraceID: request.TraceID}
	var stream *invocationStream
	if settings.InvokeMode == "RESPONSE_STREAM" {
		stream = newInvocationStream(r.Context())
		defer stream.cancel()
	}
	response.Header().Set("X-Amzn-Trace-Id", request.TraceID)
	out, wire := s.submitInvocation(r.Context(), input, stream, options)
	if wire != nil {
		status := wire.StatusCode
		if status == http.StatusNotFound || status == http.StatusForbidden {
			status = http.StatusForbidden
		}
		writeFunctionURLFailure(response, status)
		return
	}
	executedVersion = value(out.ExecutedVersion)
	functionError = out.FunctionError != nil
	if stream == nil {
		err = writeBufferedFunctionURLResponse(response, r, out, settings.Cors)
	} else {
		err = writeStreamingFunctionURLResponse(r.Context(), response, r, stream, settings.Cors)
	}
	if err != nil {
		// Returning normally would manufacture a successful terminal chunk.
		// ErrAbortHandler is net/http's documented incomplete-response path.
		panic(http.ErrAbortHandler)
	}
}

func (s *Service) authorizeInvocation(r Reader, ref FunctionReference, function FunctionRecord, urlAuthType string) *awswire.Error {
	if urlAuthType == "" {
		return s.authorizeFunction(r, "InvokeFunction", ref, function, nil)
	}
	// The fixed-principal native URL capture checks InvokeFunctionUrl, including
	// its explicit denials, but does not check the documented second action.
	return s.authorizeFunction(r, "InvokeFunctionUrl", ref, function, map[string][]string{"lambda:FunctionUrlAuthType": {urlAuthType}})
}

func writeFunctionURLFailure(w http.ResponseWriter, status int) {
	message := http.StatusText(status)
	if status == http.StatusForbidden {
		message = "Forbidden. For troubleshooting Function URL authorization issues, see: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"
	}
	writeFunctionURLJSONFailure(w, status, &message)
}

func writeFunctionURLJSONFailure(w http.ResponseWriter, status int, message *string) {
	if status == http.StatusForbidden {
		w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(struct{ Message *string }{message})
	_, _ = w.Write(body)
}

type functionURLResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *functionURLResponseWriter) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *functionURLResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *functionURLResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
