package athena

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Engine     Engine
	Results    Results
	Catalog    Catalog
	Events     QueryEvents
	Metrics    MetricPublisher
}
type Service struct {
	repository      Repository
	authorizer      authorization.Authorizer
	recorder        apievents.Recorder
	clock           clock.Clock
	engine          Engine
	results         Results
	catalog         Catalog
	events          QueryEvents
	metrics         MetricPublisher
	lifetime        context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	work            sync.WaitGroup
	started, closed bool
	running         map[ResourceKey]context.CancelFunc
	cleaning        map[ResourceKey]bool
	jobs            *scheduler.Driver
	operations      map[string]func(context.Context) (any, *awswire.Error)
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
	lifetime, cancel := context.WithCancel(context.Background())
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, engine: c.Engine, results: c.Results, catalog: c.Catalog, events: c.Events, metrics: c.Metrics, lifetime: lifetime, cancel: cancel, running: map[ResourceKey]context.CancelFunc{}, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.cleaning = map[ResourceKey]bool{}
	s.jobs = scheduler.New(c.Clock, queryJobs{s})
	registerWorkGroups(s)
	registerCatalogs(s)
	registerSavedQueries(s)
	registerQueries(s)
	registerTags(s)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for k := range s.operations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerException", "Missing generated Athena request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("athena")
	response, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, response)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement Athena Spark sessions/notebooks and capacity workflows with their distinct native engines and dependencies.
		rejected := unsupported("Athena operation is not implemented: " + action)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func registerControl[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerException", "Missing generated Athena request binding.", 500)
		}
		return runCommand(s, ctx, action, in, fn)
	}
}
func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(context.Context, Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		tx = cloudFormationTransaction(tx, ctx)
		var err error
		out, err = fn(tx.Context(), tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
		s.jobs.Wake()
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
	model, _ := awscatalog.LookupService("athena")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Athena operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return invalidRequest(invalid.Error())
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
func invalidRequest(message string) *awswire.Error {
	return failure("InvalidRequestException", message)
}
func unsupported(message string) *awswire.Error { return failure("InvalidRequestException", message) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		switch wire.Code {
		case "AccessDenied":
			return failure("AccessDeniedException", wire.Message)
		case "EntityNotFoundException":
			// Native GetDatabase/GetTableMetadata wrap missing Glue metadata.
			return failure("MetadataException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return invalidRequest("Requested resource does not exist.")
	}
	slog.Error("Athena command failed", "error", err)
	return failure("InternalServerException", "Unable to complete Athena operation.", 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func enabled[T ~bool](v *T) bool { return v != nil && bool(*v) }
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func resourceFor(ctx context.Context, name string) ResourceKey {
	return ResourceKey{Scope: scopeFor(ctx), Name: name}
}
func workGroupName(name string) string {
	if name == "" {
		return "primary"
	}
	return name
}
func queryState(v QueryRecord) string {
	if v.Data.Status == nil {
		return ""
	}
	return value(v.Data.Status.State)
}
