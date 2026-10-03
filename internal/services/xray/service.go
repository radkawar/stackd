// Package xray owns native trace ingestion, retrieval and access policies.
package xray

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Metrics      MetricPublisher
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	binder     authorization.PolicyBinder
	recorder   apievents.Recorder
	clock      clock.Clock
	metrics    MetricPublisher
	jobs       *scheduler.Driver
	operations map[string]func(context.Context) (any, *awswire.Error)
}

func New(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, metrics: c.Metrics, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, traceExpiry{s}, groupMetricJobs{s})
	register(s, "PutTraceSegments", s.putTraceSegments)
	register(s, "PutTelemetryRecords", s.putTelemetryRecords)
	register(s, "BatchGetTraces", s.batchGetTraces)
	register(s, "PutResourcePolicy", s.putResourcePolicy)
	register(s, "ListResourcePolicies", s.listResourcePolicies)
	register(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	register(s, "CreateSamplingRule", s.createSamplingRule)
	register(s, "UpdateSamplingRule", s.updateSamplingRule)
	register(s, "DeleteSamplingRule", s.deleteSamplingRule)
	register(s, "GetSamplingRules", s.getSamplingRules)
	register(s, "GetSamplingTargets", s.getSamplingTargets)
	register(s, "GetSamplingStatisticSummaries", s.getSamplingStatisticSummaries)
	register(s, "CreateGroup", s.createGroup)
	register(s, "UpdateGroup", s.updateGroup)
	register(s, "DeleteGroup", s.deleteGroup)
	register(s, "GetGroup", s.getGroup)
	register(s, "GetGroups", s.getGroups)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "GetTraceSummaries", s.getTraceSummaries)
	register(s, "GetTraceGraph", s.getTraceGraph)
	register(s, "GetServiceGraph", s.getServiceGraph)
	register(s, "GetTimeSeriesServiceStatistics", s.getTimeSeriesServiceStatistics)
	return s
}

func (s *Service) Operations() []string {
	operations := make([]string, 0, len(s.operations))
	for action := range s.operations {
		operations = append(operations, action)
	}
	slices.Sort(operations)
	return operations
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("xray")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalFailure", "Missing generated X-Ray request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement X-Ray Insights and account controls through
		// their actual consumers.
		rejected := failure("NotImplementedException", "X-Ray operation is not implemented: "+action, 501)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}

func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated X-Ray request binding.", 500)
		}
		return runCommand(s, ctx, action, in, fn)
	}
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	ingestion := action == "PutTraceSegments"
	if s.recorder != nil && ingestion {
		ctx = context.WithValue(ctx, traceAuditKey{}, &traceAudit{TraceIDs: []string{}})
	}
	if s.recorder != nil && action == "DeleteGroup" {
		ctx = context.WithValue(ctx, groupAuditKey{}, &groupAudit{})
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		out, err = fn(tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
		if ingestion || action == "GetSamplingTargets" {
			s.jobs.Wake()
		}
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}

func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	if s.recorder == nil {
		return nil
	}
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("xray")
	if err := awsapi.BindHTTP(model, operation, request, input); err != nil {
		if s.RequestError(string(operation.Name), err).Code == "InternalFailure" {
			if parameters, err := telemetryRejectionParameters(model, operation, request.Body); err == nil {
				return parameters
			}
		}
		return nil
	}
	return input
}

func (*Service) RequestError(operation string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested X-Ray operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if operation == "PutTelemetryRecords" && invalid.Constraint == "nonnull" &&
			strings.HasPrefix(invalid.Path, "TelemetryRecords[") && strings.HasSuffix(invalid.Path, "]") {
			return failure("InternalFailure", "", http.StatusInternalServerError)
		}
		if invalid.TypeMismatch {
			return failure("SerializationException", invalid.Error())
		}
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}

func failure(code, message string, status ...int) *awswire.Error {
	n := http.StatusBadRequest
	if len(status) != 0 {
		n = status[0]
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: n}
}

func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return &awswire.Error{Code: "AccessDeniedException", Message: wire.Message, StatusCode: http.StatusForbidden, Cause: wire}
		}
		return wire
	}
	slog.Error("X-Ray command failed", "error", err)
	return failure("InternalFailure", "Unable to complete X-Ray operation.", 500)
}

func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
