// Package lambda owns function deployments and authorization separately from real runtimes.
package lambda

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository           Repository
	Executor             runtime.Executor
	CodeSource           CodeSource
	Roles                RoleProvider
	SQS                  SQSSource
	DynamoDB             DynamoDBSource
	Kinesis              KinesisSource
	Kafka                KafkaSource
	MQ                   MQSource
	DocumentDB           DocumentDBSource
	Capacity             CapacityBackend
	CodeSigningAuthority CodeSigningAuthority
	SourceNetworks       SourceNetworks
	DurableEncryption    DurableEncryption
	StreamTargets        StreamTargets
	FilterEncryption     FilterEncryption
	Logs                 LogProvider
	Targets              OutcomeTargets
	Metrics              MetricPublisher
	Authorizer           authorization.Authorizer
	PolicyBinder         authorization.PolicyBinder
	Events               Events
	APIEvents            apievents.Recorder
	Clock                clock.Clock
	Endpoint             string
	// PublicEndpoint is the trusted origin serving code downloads and function URLs.
	PublicEndpoint string
	// KeepAlive zero forces a cold environment for each invocation.
	KeepAlive time.Duration
}
type Service struct {
	repository           Repository
	executor             runtime.Executor
	codeSource           CodeSource
	roles                RoleProvider
	sqs                  SQSSource
	sqsPoller            *sqsPollingKernel
	dynamoDB             DynamoDBSource
	kinesis              KinesisSource
	streamTargets        StreamTargets
	filterEncryption     FilterEncryption
	streamPoller         *streamPollingKernel
	kafka                KafkaSource
	kafkaPoller          *kafkaPollingKernel
	mq                   MQSource
	mqPoller             *mqPollingKernel
	documentDB           DocumentDBSource
	documentDBPoller     *documentDBPollingKernel
	provisioned          *provisionedKernel
	durable              *durableKernel
	capacityBackend      CapacityBackend
	capacity             *capacityKernel
	codeSigningAuthority CodeSigningAuthority
	sourceNetworks       SourceNetworks
	durableEncryption    DurableEncryption
	logs                 LogProvider
	targets              OutcomeTargets
	metrics              MetricPublisher
	authorizer           authorization.Authorizer
	binder               authorization.PolicyBinder
	events               Events
	apiEvents            apievents.Recorder
	jobs                 *scheduler.Driver
	clock                clock.Clock
	endpoint             string
	publicEndpoint       string
	keepAlive            time.Duration
	operations           map[string]func(context.Context, any) (any, *awswire.Error)
	mu                   sync.Mutex
	startMu              sync.Mutex
	environments         map[FunctionVersionKey][]*execution
	inFlight             map[Scope]*concurrencyUsage
	originMu             sync.RWMutex
	origins              map[string]*invocationEnvironment
	// Scheduler discovery runs inside a storage snapshot. Lifecycle reads must
	// not acquire mu: invocation admission holds mu before entering storage.
	closed   atomic.Bool
	started  atomic.Bool
	lifetime context.Context
	cancel   context.CancelFunc
	work     sync.WaitGroup
}

func New(config Config) *Service {
	if config.Repository == nil {
		config.Repository = NewMemoryRepository(nil)
	}
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if config.Authorizer == nil {
		config.Authorizer = authorization.NewWithClock(nil, nil, config.Clock)
	}
	if config.PolicyBinder == nil {
		config.PolicyBinder, _ = config.Authorizer.(authorization.PolicyBinder)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	s := &Service{repository: config.Repository, executor: config.Executor, roles: config.Roles, authorizer: config.Authorizer, clock: config.Clock, endpoint: config.Endpoint, keepAlive: config.KeepAlive, lifetime: lifetime, cancel: cancel, environments: map[FunctionVersionKey][]*execution{}, inFlight: map[Scope]*concurrencyUsage{}, operations: map[string]func(context.Context, any) (any, *awswire.Error){}}
	s.binder, s.events = config.PolicyBinder, config.Events
	s.apiEvents = config.APIEvents
	s.publicEndpoint = config.PublicEndpoint
	s.logs = config.Logs
	s.targets, s.metrics = config.Targets, config.Metrics
	s.codeSource = config.CodeSource
	s.sqs = config.SQS
	s.dynamoDB, s.streamTargets = config.DynamoDB, config.StreamTargets
	s.kinesis = config.Kinesis
	s.kafka = config.Kafka
	s.mq, s.documentDB = config.MQ, config.DocumentDB
	s.durable = newDurableKernel(s)
	s.capacityBackend, s.capacity = config.Capacity, newCapacityKernel(s)
	s.codeSigningAuthority = config.CodeSigningAuthority
	s.sourceNetworks = config.SourceNetworks
	s.durableEncryption = config.DurableEncryption
	s.filterEncryption = config.FilterEncryption
	s.jobs = scheduler.New(config.Clock, eventInvokeConfigJobs{s}, eventSourceMappingJobs{s}, invocationJobs{s}, outcomeJobs{s}, metricJobs{s}, codeArchiveJobs{s}, codeSourceJobs{s}, durableJobs{s}, capacityJobs{s})
	register(s, "CreateFunction", s.createFunction)
	register(s, "GetFunctionConfiguration", s.getConfiguration)
	register(s, "GetFunction", s.getFunction)
	register(s, "ListFunctions", s.listFunctions)
	register(s, "DeleteFunction", s.deleteFunction)
	register(s, "Invoke", s.invoke)
	register(s, "InvokeAsync", s.invokeAsync)
	register(s, "InvokeWithResponseStream", s.invokeWithResponseStream)
	register(s, "UpdateFunctionCode", s.updateCode)
	register(s, "UpdateFunctionConfiguration", s.updateConfiguration)
	s.registerPermissions()
	s.registerEventInvokeConfig()
	s.registerFunctionURLs()
	s.registerEventSourceMappings()
	s.registerConcurrency()
	s.registerTags()
	s.registerVersions()
	s.registerAliases()
	s.registerLayers()
	s.registerRuntimeControls()
	s.registerCodeSigning()
	s.registerDurable()
	s.registerCapacity()
	return s
}
func register[I, O any](s *Service, name string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, in any) (any, *awswire.Error) {
		if s.apiEvents != nil {
			var err error
			ctx, err = apievents.Reserve(ctx)
			if err != nil {
				return nil, wireError(err)
			}
		}
		if name == "CreateFunction" || name == "UpdateFunctionCode" || name == "UpdateFunctionConfiguration" {
			ctx = withCodeSigningAudit(ctx)
		}
		out, wire := fn(ctx, in.(*I))
		// A partial result with an error represents committed native effects;
		// that command records its error outcome in the same transaction.
		record := wire != nil && out == nil || auditProjections[name].ReadOnly
		if name == "Invoke" && wire == nil {
			kind := value(in.(*api.InvokeInput).InvocationType)
			record = kind != "Event" && kind != "DryRun"
		}
		if name == "InvokeWithResponseStream" {
			record = true
		}
		if record && s.apiEvents != nil {
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if err := s.recordCall(completion, name, in, out, wire); err != nil {
				return nil, wireError(err)
			}
		}
		return out, wire
	}
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func (s *Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("ResourceNotFoundException", "Unknown Lambda operation.", 404)
	}
	if errors.Is(err, awsapi.ErrUnsupportedBinding) {
		return unsupported(err.Error())
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if invalid.TypeMismatch {
			return failure("SerializationException", invalid.Error(), 400)
		}
		if invalid.Constraint != "" {
			return failure("ValidationException", invalid.Error(), 400)
		}
	}
	return failure("InvalidParameterValueException", err.Error(), 400)
}

func (s *Service) dispatch(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	handler, ok := s.operations[string(decoded.Operation.Name)]
	if !ok {
		// TODO: Comeback implement remaining targeted Lambda operations and event sources without substituting metadata-only success.
		return nil, unsupported("Lambda operation is not implemented: " + string(decoded.Operation.Name))
	}
	return handler(awsapi.WithDecodedRequest(ctx, decoded), decoded.Input)
}

// responseContext links delivery to shutdown without shortening the accepted
// invocation's independent execution lifetime.
func (s *Service) responseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// ExecuteCommand returns the generated output, including the live event stream.
// Stream delivery owns the response context until completion or cancellation.
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	output, _, wire := s.executeCommand(ctx, decoded, false)
	return output, wire
}

// ExecuteCommandResponse returns generated output and the same encoded response
// as the Lambda frontend. Body borrows the output payload until delivery completes.
// Streaming callers consume either the modeled event channel or response.Stream
// and must cancel ctx if they abandon delivery.
func (s *Service) ExecuteCommandResponse(ctx context.Context, decoded awsapi.DecodedRequest) (any, awsapi.HTTPResponse, *awswire.Error) {
	return s.executeCommand(ctx, decoded, true)
}

func (s *Service) executeCommand(ctx context.Context, decoded awsapi.DecodedRequest, encode bool) (any, awsapi.HTTPResponse, *awswire.Error) {
	ctx, release := s.responseContext(ctx)
	output, wire := s.dispatch(ctx, decoded)
	if wire != nil {
		release()
		return nil, awsapi.HTTPResponse{}, wire
	}
	var response awsapi.HTTPResponse
	if encode {
		model, _ := awscatalog.LookupService("lambda")
		response, wire = encodeResponse(ctx, model, decoded.Operation, output)
		if wire != nil {
			release()
			return nil, awsapi.HTTPResponse{}, wire
		}
	}
	if stream, ok := output.(*invocationStream); ok {
		context.AfterFunc(stream.ctx, release)
	} else {
		release()
	}
	if native, ok := output.(interface{ modeledOutput() any }); ok {
		output = native.modeledOutput()
	}
	return output, response, nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("lambda")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("ServiceException", "Missing generated request.", 500))
		return
	}
	// Provider shutdown must release delivery workers and interrupt blocked
	// stream writes, independently of the accepted invocation's lifetime.
	ctx, cancel := s.responseContext(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	output, wire := s.dispatch(r.Context(), decoded)
	if wire != nil {
		awswire.RESTJSONError(w, r, &model, wire)
		return
	}
	response, wire := encodeResponse(r.Context(), model, decoded.Operation, output)
	if wire != nil {
		awswire.RESTJSONError(w, r, &model, wire)
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	if response.Stream != nil {
		_ = response.Stream(r.Context(), w)
	} else {
		_, _ = w.Write(response.Body)
	}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}
func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			copy := *wire
			copy.Code = "AccessDeniedException"
			return &copy
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Function not found.", 404)
	}
	return failure("ServiceException", err.Error(), 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
