package autoscaling

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

const Namespace = "http://autoscaling.amazonaws.com/doc/2011-01-01/"

type Config struct {
	Repository          Repository
	Authorizer          authorization.Authorizer
	Recorder            apievents.Recorder
	Clock               clock.Clock
	Roles               ServiceRoles
	Instances           Instances
	Identity            ExecutionIdentity
	TargetGroups        TargetGroups
	Events              Events
	Metrics             MetricPublisher
	Alarms              Alarms
	TerminationSelector TerminationSelector
}

type Service struct {
	repository          Repository
	authorizer          authorization.Authorizer
	recorder            apievents.Recorder
	clock               clock.Clock
	roles               ServiceRoles
	instances           Instances
	identity            ExecutionIdentity
	targetGroups        TargetGroups
	events              Events
	metrics             MetricPublisher
	alarms              Alarms
	terminationSelector TerminationSelector
	jobs                *scheduler.Driver
	effects             *groupEffects
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
	s := &Service{
		repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock,
		roles: c.Roles, instances: c.Instances, identity: c.Identity, targetGroups: c.TargetGroups,
		events: c.Events, metrics: c.Metrics, alarms: c.Alarms,
		terminationSelector: c.TerminationSelector,
		effects:             newGroupEffects(), operations: map[string]func(context.Context) (any, *awswire.Error){},
	}
	registerGroups(s)
	registerMembership(s)
	registerTags(s)
	registerPolicies(s)
	registerSchedules(s)
	registerHooks(s)
	registerMetrics(s)
	registerWarmPool(s)
	registerRefresh(s)
	s.jobs = scheduler.New(c.Clock, groupJobs{s}, scheduleJobs{s}, lifecycleJobs{s})
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for operation := range s.operations {
		out = append(out, operation)
	}
	slices.Sort(out)
	return out
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated Auto Scaling request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.QueryError(w, r, Namespace, rejected)
		return
	}
	model, _ := awscatalog.LookupService("autoscaling")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.QueryError(w, r, Namespace, wireError(err))
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, string(decoded.Operation.Name), body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	if handler := s.operations[string(decoded.Operation.Name)]; handler != nil {
		return handler(ctx)
	}
	// TODO: Comeback implement predictive scaling,
	// mixed/Spot capacity and the remaining generated Auto Scaling operations.
	rejected := unsupported("The requested Auto Scaling operation is not implemented.")
	if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func register[I, O any](s *Service, action string, command func(context.Context, Transaction, *I) (*O, error)) {
	registerPrepared(s, action, func(ctx context.Context, in *I) (func(Transaction) (*O, error), error) {
		return func(tx Transaction) (*O, error) {
			return command(tx.Context(), tx, in)
		}, nil
	})
}

// registerPrepared keeps dependency admission outside the write transaction,
// while the accepted state transition and its API event commit together.
func registerPrepared[I, O any](s *Service, action string, prepare func(context.Context, *I) (func(Transaction) (*O, error), error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated Auto Scaling input.")
		}
		out, err := executePrepared(s, ctx, action, in, prepare)
		if err != nil {
			return nil, wireError(err)
		}
		return out, nil
	}
}

func executePrepared[I, O any](s *Service, ctx context.Context, action string, in *I, prepare func(context.Context, *I) (func(Transaction) (*O, error), error)) (*O, error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, auditContextKey{}, &auditContext{})
	var out *O
	command, err := prepare(ctx, in)
	// A managed scale-down replay is not an UpdateAutoScalingGroup call.
	if errors.Is(err, errManagedScalingUnchanged) {
		return nil, err
	}
	if err == nil {
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			tx = bindCloudFormationOwnership(tx)
			var err error
			out, err = command(tx)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
	}
	if err == nil {
		s.jobs.Wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		if err := dependency.RecordRejection(completion); err != nil {
			return nil, err
		}
	}
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, err
	}
	return nil, err
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}

func (*Service) RequestErrorInput(op awscatalog.Operation, request awsapi.Request) any {
	input, err := api.NewInput(string(op.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("autoscaling")
	if awsapi.Decode(model, op, request, input) != nil {
		return nil
	}
	return input
}

func (*Service) RequestError(_ string, err error) *awswire.Error { return invalid(err.Error()) }

func scopeFor(ctx context.Context) Scope {
	metadata := awsctx.FromContext(ctx)
	return Scope{metadata.Partition, metadata.AccountID, metadata.Region}
}

func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalFailure" {
		status = http.StatusInternalServerError
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error { return failure("ValidationError", message) }
func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "NotImplemented", Message: message, StatusCode: http.StatusNotImplemented}
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		return rejected
	}
	return failure("InternalFailure", "Unable to access Auto Scaling state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func intValue[T ~int32 | ~int64](v *T) int64 {
	if v == nil {
		return 0
	}
	return int64(*v)
}
func text[T ~string](p **T, v string)          { x := T(v); *p = &x }
func number[T ~int32 | ~int64](p **T, v int64) { x := T(v); *p = &x }
func boolean[T ~bool](p **T, v bool)           { x := T(v); *p = &x }
func plainList[S ~[]E, E ~string](values S) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}
