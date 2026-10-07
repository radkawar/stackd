package applicationautoscaling

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Roles      ServiceRoles
	Resources  Resources
	Identity   ExecutionIdentity
	Alarms     Alarms
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	roles      ServiceRoles
	resources  Resources
	identity   ExecutionIdentity
	alarms     Alarms
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, roles: c.Roles, resources: c.Resources, identity: c.Identity, alarms: c.Alarms, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, targetJobs{s}, scheduleJobs{s}, activityJobs{s})
	register(s, "RegisterScalableTarget", s.registerScalableTarget)
	register(s, "DescribeScalableTargets", s.describeScalableTargets)
	register(s, "DeregisterScalableTarget", s.deregisterScalableTarget)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "PutScalingPolicy", s.putScalingPolicy)
	register(s, "DescribeScalingPolicies", s.describeScalingPolicies)
	register(s, "DeleteScalingPolicy", s.deleteScalingPolicy)
	register(s, "PutScheduledAction", s.putScheduledAction)
	register(s, "DescribeScheduledActions", s.describeScheduledActions)
	register(s, "DeleteScheduledAction", s.deleteScheduledAction)
	register(s, "DescribeScalingActivities", s.describeScalingActivities)
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

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
		awswire.JSONError(w, r, failure("InternalServiceException", "Missing generated Application Auto Scaling request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("applicationautoscaling")
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
	handler, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement predictive forecast queries.
		rejected := unsupported("Application Auto Scaling operation is not implemented: " + action)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return handler(ctx)
}

func register[I, O any](s *Service, action string, command func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServiceException", "Missing generated Application Auto Scaling request binding.")
		}
		return runCommand(s, ctx, action, in, command)
	}
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, command func(context.Context, Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *O
	err = s.repository.Update(ctx, func(tx Transaction) error {
		tx = bindCloudFormationOwnership(tx)
		var err error
		out, err = command(tx.Context(), tx, in)
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
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		if err := dependency.RecordRejection(completion); err != nil {
			return nil, wireError(err)
		}
	}
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("applicationautoscaling")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get")}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	call.AdditionalEventData = []byte(`{"service":"application-autoscaling"}`)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested operation is not recognized.")
	}
	var invalidInput *awsapi.ValidationError
	if errors.As(err, &invalidInput) {
		return invalid(invalidInput.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}

func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	model, _ := awscatalog.LookupService("applicationautoscaling")
	if shape, ok := model.ErrorShape(code); ok && shape.Error.HTTPStatus != 0 {
		status = shape.Error.HTTPStatus
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error { return failure("ValidationException", message) }
func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "NotImplementedException", Message: message, StatusCode: http.StatusNotImplemented}
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
	return failure("InternalServiceException", "Unable to access Application Auto Scaling state.")
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
