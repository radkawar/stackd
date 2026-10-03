// Package rdsdata exposes the generated RDS Data API over native SQL sessions.
package rdsdata

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"stackd/clock"
	engine "stackd/engine/rds"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// Cluster is a current, scope-checked control-plane view, never secret metadata.
type Cluster struct {
	ARN, Engine, Database, Status string
	Endpoint                      engine.Endpoint
	HTTPEnabled                   bool
	Tags                          map[string]string
}
type ClusterResolver interface {
	ResolveDataCluster(context.Context, string) (Cluster, error)
}

// SecretResolver retrieves ordinary Secrets Manager credentials under the current
// caller, including independent resource-tag and KMS authorization. Names are
// resolved in the caller's scope. Secret host/port/database fields are not used.
type SecretResolver interface {
	Credentials(context.Context, string) (username, password string, err error)
}
type Config struct {
	Clusters   ClusterResolver
	Secrets    SecretResolver
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
}
type Service struct {
	clusters     ClusterResolver
	secrets      SecretResolver
	authorizer   authorization.Authorizer
	recorder     apievents.Recorder
	clock        clock.Clock
	jobs         *scheduler.Driver
	lifetime     context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	closed       bool
	work         sync.WaitGroup
	transactions map[string]*transaction
	operations   map[string]func(context.Context) (any, error)
}

func New(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{clusters: c.Clusters, secrets: c.Secrets, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, lifetime: ctx, cancel: cancel, transactions: map[string]*transaction{}, operations: map[string]func(context.Context) (any, error){}}
	s.jobs = scheduler.New(c.Clock, transactionJobs{s})
	register(s, "ExecuteStatement", s.execute)
	register(s, "BatchExecuteStatement", s.batch)
	register(s, "BeginTransaction", s.begin)
	register(s, "CommitTransaction", s.commit)
	register(s, "RollbackTransaction", s.rollback)
	return s
}
func register[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated RDS Data API request binding.", 500)
		}
		return fn(ctx, in)
	}
}
func (*Service) Operations() []string {
	return []string{"BatchExecuteStatement", "BeginTransaction", "CommitTransaction", "ExecuteStatement", "RollbackTransaction"}
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return scheduler.ErrClosed
	}
	s.jobs.Start()
	return nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.jobs.Close()
	s.work.Wait()
	s.mu.Lock()
	remaining := s.transactions
	s.transactions = map[string]*transaction{}
	s.mu.Unlock()
	var result error
	for _, t := range remaining {
		result = errors.Join(result, t.close(false))
	}
	return result
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Missing generated RDS Data API request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("rdsdata")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Unable to encode response.", 500))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, failure("ServiceUnavailableError", "The service is closed.", 503)
	}
	s.work.Add(1)
	s.mu.Unlock()
	defer s.work.Done()
	ctx = awsapi.WithDecodedRequest(ctx, request)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	defer cancel()
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, failure("InternalServerErrorException", "Unable to reserve operation.", 500)
	}
	var out any
	action := string(request.Operation.Name)
	if fn := s.operations[action]; fn != nil {
		out, err = fn(ctx)
	} else {
		err = failure("BadRequestException", "ExecuteSql is not supported; use ExecuteStatement.")
	}
	rejected := wireError(err)
	completion, done := apievents.CompletionContext(ctx)
	defer done()
	// Native SQL effects cannot participate in the metadata repository's commit.
	// Record their observed completion in an independent journal transaction.
	if err := s.recordCall(completion, action, request.Input, rejected); err != nil {
		return nil, failure("InternalServerErrorException", "Unable to record operation outcome.", 500)
	}
	return out, rejected
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, e)
}
func (s *Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	if s.recorder == nil {
		return nil
	}
	in, err := api.NewInput(string(op.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("rdsdata")
	if awsapi.BindJSON(model, op.Input, r.JSON, in) != nil {
		return nil
	}
	return in
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown RDS Data API operation.")
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		return failure("BadRequestException", validation.Error())
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
			return failure("AccessDeniedException", wire.Message, 403)
		}
		return wire
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure("StatementTimeoutException", "The SQL statement timed out.")
	}
	if errors.Is(err, context.Canceled) {
		return failure("DatabaseErrorException", "The SQL statement was cancelled.")
	}
	// Only errors from the native driver reach this boundary; do not replace them
	// with successful empty records or expose them in diagnostic logs.
	return failure("DatabaseErrorException", err.Error())
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func enabled(v *api.Boolean) bool { return v != nil && bool(*v) }
