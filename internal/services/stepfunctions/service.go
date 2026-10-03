package stepfunctions

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/stepfunctions/asl"
)

// TaskDependencies admits service-managed integration resources under the
// workflow role, outside the state-machine resource transaction.
type TaskDependencies interface {
	ConfigureTaskDependencies(context.Context, RevisionRecord) error
}

type Config struct {
	Repository       Repository
	Authorizer       authorization.Authorizer
	Recorder         apievents.Recorder
	Clock            clock.Clock
	Tasks            TaskRunner
	TaskDependencies TaskDependencies
	Events           ExecutionEventPublisher
	History          HistoryPublisher
	Metrics          MetricPublisher
	Tracing          TracePublisher
	EncryptionKeys   EncryptionKeys
}

type Service struct {
	repository       Repository
	authorizer       authorization.Authorizer
	recorder         apievents.Recorder
	clock            clock.Clock
	tasks            TaskRunner
	taskDependencies TaskDependencies
	events           ExecutionEventPublisher
	history          HistoryPublisher
	metrics          MetricPublisher
	tracing          TracePublisher
	encryption       workflowEncryption
	admission        workflowAdmission
	jobs             *scheduler.Driver
	operations       map[string]func(context.Context, any) (any, *awswire.Error)
	ctx              context.Context
	cancel           context.CancelCauseFunc
	workers          sync.WaitGroup
	mu               sync.Mutex
	active           map[TaskKey]context.CancelFunc
	changed          chan struct{}
	closed           bool
	recovered        bool
	definitions      sync.Map // immutable compiled definitions, keyed by revision ID
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
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &Service{
		repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder,
		clock: c.Clock, tasks: c.Tasks, events: c.Events, history: c.History, metrics: c.Metrics,
		taskDependencies: c.TaskDependencies,
		tracing:          c.Tracing,
		encryption:       workflowEncryption{keys: c.EncryptionKeys, clock: c.Clock},
		operations:       map[string]func(context.Context, any) (any, *awswire.Error){},
		ctx:              ctx, cancel: cancel, active: map[TaskKey]context.CancelFunc{}, changed: make(chan struct{}),
	}
	s.jobs = scheduler.New(c.Clock, workflowJobs{s})
	s.registerControlOperations()
	s.registerExecutionOperations()
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.cancel(ErrTaskInterrupted)
		close(s.changed)
	}
	s.mu.Unlock()
	s.jobs.Close()
	s.workers.Wait()
	s.encryption.close()
	return nil
}

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, internalFailure())
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("stepfunctions")
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, internalFailure())
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
	fn, ok := s.operations[string(decoded.Operation.Name)]
	if !ok {
		return nil, failure("NotImplementedException", "Step Functions operation is not implemented: "+string(decoded.Operation.Name), 501)
	}
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out any
	var rejected *awswire.Error
	action := string(decoded.Operation.Name)
	// StartExecution selects its Standard/Express bucket after resolving the
	// machine. All other API callers share this admission boundary.
	if action != "StartExecution" {
		scope := scopeFor(ctx)
		if quota, limited := workflowQuotaFor(action, scope.Region); limited &&
			s.admission.admit(scope, action, s.clock.Now(), quota) != 0 {
			rejected = failure("ThrottlingException", "Rate exceeded", 400)
		}
	}
	if rejected == nil {
		out, rejected = fn(ctx, decoded.Input)
	}
	if rejected != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.recordCall(completion, string(decoded.Operation.Name), decoded.Input, nil, rejected); err != nil {
			return nil, wireError(err)
		}
	}
	return out, rejected
}

func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context, input any) (any, *awswire.Error) {
		output, err := executeRecordedCommand(s, ctx, action, input.(*I), fn)
		return output, wireError(err)
	}
}

// executeRecordedCommand commits successful commands and their native API outcome
// together. A failed attempt retains its original error for admission handoffs.
func executeRecordedCommand[I, O any](s *Service, ctx context.Context, action string, input *I, fn func(Transaction, *I) (*O, error)) (*O, error) {
	var output *O
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		output, err = fn(tx, input)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, input, output, nil)
	})
	if err == nil {
		s.notify()
	}
	return output, err
}

func (s *Service) notify() {
	s.mu.Lock()
	if !s.closed {
		close(s.changed)
		s.changed = make(chan struct{})
	}
	s.mu.Unlock()
	s.jobs.Wake()
}

func (s *Service) compiled(revision RevisionRecord) (*asl.Definition, error) {
	if cached, ok := s.definitions.Load(revision.Key); ok {
		return cached.(*asl.Definition), nil
	}
	definition, diagnostics := asl.Compile(revision.Definition)
	if definition == nil {
		return nil, errors.New("retained Step Functions definition is invalid: " + diagnostics[0].Message)
	}
	actual, _ := s.definitions.LoadOrStore(revision.Key, definition)
	return actual.(*asl.Definition), nil
}

func (s *Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown operation", 400)
	}
	return failure("ValidationException", err.Error(), 400)
}

func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func invalid(message string) *awswire.Error { return failure("ValidationException", message, 400) }
func internalFailure() *awswire.Error {
	return failure("InternalServerError", "Unable to access Step Functions state.", 500)
}

func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		return rejected
	}
	return internalFailure()
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
