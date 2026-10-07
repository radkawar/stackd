package glue

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository        Repository
	Authorizer        authorization.Authorizer
	PolicyBinder      authorization.PolicyBinder
	Recorder          apievents.Recorder
	Clock             clock.Clock
	JobRuntime        JobRuntime
	JobDependencies   JobDependencies
	CrawlerSource     CrawlerSource
	JobEvents         JobEvents
	CrawlerEvents     CrawlerEvents
	CatalogEvents     CatalogEvents
	ConnectionSecrets ConnectionSecrets
	ConnectionCrypto  ConnectionCrypto
}

type Service struct {
	repository        Repository
	authorizer        authorization.Authorizer
	binder            authorization.PolicyBinder
	recorder          apievents.Recorder
	clock             clock.Clock
	jobRuntime        JobRuntime
	jobDependencies   JobDependencies
	crawlerSource     CrawlerSource
	jobEvents         JobEvents
	crawlerEvents     CrawlerEvents
	catalogEvents     CatalogEvents
	connectionSecrets ConnectionSecrets
	connectionCrypto  ConnectionCrypto
	crawlerMu         sync.Mutex
	crawlerActive     map[ResourceKey]context.CancelFunc
	lifetime          context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	work              sync.WaitGroup
	started, closed   bool
	jobs              *scheduler.Driver
	operations        map[string]func(context.Context) (any, *awswire.Error)
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
	lifetime, cancel := context.WithCancel(context.Background())
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, jobRuntime: c.JobRuntime, jobDependencies: c.JobDependencies, crawlerSource: c.CrawlerSource, lifetime: lifetime, cancel: cancel, crawlerActive: map[ResourceKey]context.CancelFunc{}, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobEvents = c.JobEvents
	s.crawlerEvents = c.CrawlerEvents
	s.catalogEvents = c.CatalogEvents
	s.connectionSecrets = c.ConnectionSecrets
	s.connectionCrypto = c.ConnectionCrypto
	s.jobs = scheduler.New(c.Clock, jobRunJobs{s}, crawlerJobs{s}, registryJobs{s}, workflowJobs{s})
	registerCatalog(s)
	registerJobs(s)
	registerCrawlers(s)
	registerRegistry(s)
	registerWorkflows(s)
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
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Start() error {
	if err := s.recoverCrawlers(s.lifetime); err != nil {
		return err
	}
	if err := s.recoverJobs(s.lifetime); err != nil {
		return err
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	s.jobs.Wake()
	return nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.jobs.Close()
	s.work.Wait()
	return nil
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServiceException", "Missing generated Glue request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("glue")
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
		rejected := unsupported("Glue operation is not implemented: " + action)
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
			return nil, failure("InternalServiceException", "Missing generated Glue input.", 500)
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
		route, err := s.routeCatalogCommand(tx.Context(), tx, action, in)
		if err != nil {
			return err
		}
		if route.hasOutput {
			var ok bool
			out, ok = route.output.(*O)
			if !ok {
				return errors.New("glue catalog link result type mismatch")
			}
		} else {
			resolved, ok := route.input.(*I)
			if !ok {
				return errors.New("glue catalog link input type mismatch")
			}
			out, err = fn(route.ctx, tx, resolved)
			if err != nil {
				return err
			}
		}
		if err := s.followCatalogResult(tx, route, out); err != nil {
			return err
		}
		if err := s.publishCatalogCall(route.ctx, action, route.input); err != nil {
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
	model, _ := awscatalog.LookupService("glue")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Glue operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("InvalidInputException", invalid.Error())
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
func unsupported(message string) *awswire.Error { return failure("InvalidInputException", message) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("EntityNotFoundException", "Requested Glue resource was not found.")
	}
	slog.Error("Glue command failed", "error", err)
	return failure("InternalServiceException", "Unable to complete Glue operation.", 500)
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
func catalogKey(ctx context.Context, id *api.CatalogIdString) CatalogKey {
	return catalogKeyIn(scopeFor(ctx), value(id))
}
func catalogKeyIn(scope Scope, catalog string) CatalogKey {
	if catalog == "" {
		catalog = scope.AccountID
	}
	account, _, _ := strings.Cut(catalog, ":")
	scope.AccountID = account
	return CatalogKey{Scope: scope, CatalogID: catalog}
}
func databaseKey(ctx context.Context, id *api.CatalogIdString, name *api.NameString) DatabaseKey {
	return DatabaseKey{CatalogKey: catalogKey(ctx, id), Name: strings.ToLower(value(name))}
}
func tableKey(ctx context.Context, id *api.CatalogIdString, db, name *api.NameString) TableKey {
	return TableKey{DatabaseKey: databaseKey(ctx, id, db), TableName: strings.ToLower(value(name))}
}
