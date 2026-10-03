package kinesis

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"stackd/clock"
	engine "stackd/engine/kinesis"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kinesis"
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
	Runtime      engine.Runtime
	Keys         EncryptionKeys
	Metrics      MetricPublisher
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	binder     authorization.PolicyBinder
	recorder   apievents.Recorder
	clock      clock.Clock
	runtime    engine.Runtime
	keys       EncryptionKeys
	metrics    MetricPublisher
	engines    *engineController
	admission  *admission
	encryption *encryptionCache
	consumers  *subscriptions
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, keys: c.Keys, metrics: c.Metrics, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.admission = newAdmission(c.Clock)
	s.encryption = newEncryptionCache()
	s.consumers = newSubscriptions()
	s.engines = newEngineController(s)
	s.jobs = scheduler.New(c.Clock, metricJobs{s})
	registerControls(s)
	registerResharding(s)
	registerConsumers(s)
	registerEncryption(s)
	registerData(s)
	return s
}

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for action := range s.operations {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalFailure", "Missing generated Kinesis request binding.", 500))
		return
	}
	action := string(decoded.Operation.Name)
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(s.engines.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	out, rejected := s.ExecuteCommand(ctx, decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("kinesis")
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	for name, values := range response.Header {
		w.Header()[name] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(ctx).RequestID)
	w.WriteHeader(response.StatusCode)
	if response.Stream != nil {
		if err := response.Stream(ctx, w); err != nil && ctx.Err() == nil {
			slog.Error("Kinesis event stream failed", "operation", action, "error", err)
		}
	} else {
		_, _ = w.Write(response.Body)
	}
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// Delivery channels are outside the current pinned service target; their
		// generated recognition must not masquerade as implemented behavior.
		rejected := failure("NotImplementedException", "Kinesis operation is not implemented: "+action, 501)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}

func registerOperation[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated Kinesis request binding.", 500)
		}
		return fn(ctx, in)
	}
}

func registerControl[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	registerOperation(s, action, func(ctx context.Context, in *I) (*O, *awswire.Error) {
		return runCommand(s, ctx, action, in, fn)
	})
}

func registerExternal[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	registerOperation(s, action, func(ctx context.Context, in *I) (*O, *awswire.Error) {
		return runExternal(s, ctx, action, in, fn)
	})
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
	model, _ := awscatalog.LookupService("kinesis")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Kinesis operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}

func failure(code, message string, status ...int) *awswire.Error {
	n := http.StatusBadRequest
	if len(status) > 0 {
		n = status[0]
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: n}
}

func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Requested resource not found.")
	}
	slog.Error("Kinesis command failed", "error", err)
	return failure("InternalFailure", "Unable to complete Kinesis operation.", 500)
}

func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
