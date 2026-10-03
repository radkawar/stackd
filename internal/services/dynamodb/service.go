package dynamodb

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"stackd/clock"
	engine "stackd/engine/dynamodb"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// TableCapacityObserver receives capacity only after the external engine has
// applied it. The callback joins the control-state transaction.
type TableCapacityObserver interface {
	ObserveTableCapacity(context.Context, TableKey, *api.TableDescription) error
}

type Config struct {
	Repository          Repository
	Authorizer          authorization.Authorizer
	PolicyBinder        authorization.PolicyBinder
	Recorder            apievents.Recorder
	Clock               clock.Clock
	Runtime             engine.Runtime
	Regions             RegionAccess
	Roles               ServiceRoles
	ReplicationIdentity ReplicationIdentity
	ReplicaScaling      ReplicaScaling
	CapacityState       TableCapacityObserver
	Metrics             MetricPublisher
	Kinesis             KinesisStreams
	KinesisIdentity     KinesisIdentity
}

type Service struct {
	repository          Repository
	authorizer          authorization.Authorizer
	binder              authorization.PolicyBinder
	recorder            apievents.Recorder
	clock               clock.Clock
	runtime             engine.Runtime
	regions             RegionAccess
	roles               ServiceRoles
	replicationIdentity ReplicationIdentity
	replicaScaling      ReplicaScaling
	capacityState       TableCapacityObserver
	engines             *engineController
	metrics             MetricPublisher
	kinesis             KinesisStreams
	kinesisIdentity     KinesisIdentity
	admission           *capacityAdmission
	backupRequests      backupRequestAdmission
	jobs                *scheduler.Driver
	operations          map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.capacityState = c.CapacityState
	s.replicaScaling = c.ReplicaScaling
	s.metrics = c.Metrics
	s.kinesis, s.kinesisIdentity = c.Kinesis, c.KinesisIdentity
	s.regions, s.roles, s.replicationIdentity = c.Regions, c.Roles, c.ReplicationIdentity
	s.admission = newCapacityAdmission(c.Clock)
	s.jobs = scheduler.New(c.Clock, tableMetricJobs{s}, metricJobs{s}, kinesisJobs{s})
	s.engines = newEngineController(s)
	registerControls(s)
	registerData(s)
	registerKinesis(s)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for op := range s.operations {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerError", "Missing generated DynamoDB request binding.", 500))
		return
	}
	// Discovery advertises the transport endpoint only for HTTP callers.
	ctx := context.WithValue(r.Context(), endpointHostKey{}, r.Host)
	out, rejected := s.ExecuteCommand(ctx, decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("dynamodb")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback complete remaining DynamoDB continuous recovery, replication and external
		// service dependencies; generated recognition alone is not implementation.
		rejected := unsupported("DynamoDB operation requires an unimplemented service dependency: " + action)
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
			return nil, failure("InternalServerError", "Missing generated DynamoDB request binding.", 500)
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
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		if s.recorder != nil {
			ctx = withAuditTables(ctx)
		}
		ctx = s.withDataMetrics(ctx)
		out, err := fn(ctx, in)
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if recordErr := s.completeExternal(completion, action, in, out, rejected); recordErr != nil {
			return nil, wireError(recordErr)
		}
		return out, rejected
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
	model, _ := awscatalog.LookupService("dynamodb")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested DynamoDB operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func failure(code, message string, status ...int) *awswire.Error {
	n := 400
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
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Requested resource not found")
	}
	slog.Error("DynamoDB command failed", "error", err)
	return failure("InternalServerError", "Unable to complete DynamoDB operation.", 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
