package firehose

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
	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/firehose"
	kinesisapi "stackd/internal/awsapi/kinesis"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// S3Destination validates through joined IAM/S3 metadata commands. Write runs
// outside Firehose transactions and enters the ordinary authorized S3 command.
type S3Destination interface {
	Validate(context.Context, StreamKey, api.ExtendedS3DestinationDescription) *awswire.Error
	Write(context.Context, BufferRecord, []byte) *awswire.Error
}

// KinesisStreams keeps source authorization, retention and engine bytes in
// Kinesis. Only Describe is metadata-only and may join a control transaction.
type KinesisStreams interface {
	Describe(context.Context, StreamKey, KinesisSourceRecord) (*kinesisapi.StreamDescription, *awswire.Error)
	Iterator(context.Context, StreamKey, KinesisSourceRecord, *kinesisapi.GetShardIteratorInput) (*kinesisapi.GetShardIteratorOutput, *awswire.Error)
	Records(context.Context, StreamKey, KinesisSourceRecord, *kinesisapi.GetRecordsInput) (*kinesisapi.GetRecordsOutput, *awswire.Error)
}

// DiagnosticPublisher writes native delivery diagnostics under the configured
// Firehose destination role, not under the stream creator's identity.
type DiagnosticPublisher interface {
	Report(context.Context, StreamRecord, string, string) error
}

type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

// LambdaProcessor invokes the ordinary synchronous Lambda command under the
// configured Firehose execution role, outside service transactions.
type LambdaProcessor interface {
	Invoke(ctx context.Context, stream StreamKey, functionARN, roleARN string, payload []byte) (*lambdaapi.InvokeOutput, *awswire.Error)
}

type Config struct {
	Repository  Repository
	Authorizer  authorization.Authorizer
	Recorder    apievents.Recorder
	Clock       clock.Clock
	Destination S3Destination
	Source      KinesisStreams
	Diagnostics DiagnosticPublisher
	Metrics     MetricPublisher
	Processor   LambdaProcessor
}

type Service struct {
	repository  Repository
	authorizer  authorization.Authorizer
	recorder    apievents.Recorder
	clock       clock.Clock
	destination S3Destination
	source      KinesisStreams
	diagnostics DiagnosticPublisher
	metrics     MetricPublisher
	processor   LambdaProcessor
	lifetime    context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	work        sync.WaitGroup
	started     bool
	closed      bool
	jobs        *scheduler.Driver
	operations  map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, destination: c.Destination, source: c.Source, diagnostics: c.Diagnostics, metrics: c.Metrics, processor: c.Processor, lifetime: lifetime, cancel: cancel, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, lifecycleJobs{s}, deliveryJobs{s}, processingJobs{s}, sourceJobs{s}, metricJobs{s})
	registerControls(s)
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

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalFailure", "Missing generated Firehose request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("firehose")
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
		// TODO: Comeback implement Firehose stream encryption and additional source/destination command families with their real dependencies.
		rejected := unsupported("Firehose operation is not implemented: " + action)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}

func registerControl[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated Firehose request binding.", 500)
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
	model, _ := awscatalog.LookupService("firehose")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Firehose operation is not recognized.")
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
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
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
	slog.Error("Firehose command failed", "error", err)
	return failure("ServiceUnavailableException", "Unable to complete Firehose operation.", 500)
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
