package cloudcontrol

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudcontrol"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudformation"
	"stackd/journal"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Clock      clock.Clock
	Handlers   map[string]cloudformation.ResourceHandler
	Roles      cloudformation.ExecutionRoles
	Recorder   apievents.Recorder
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	clock      clock.Clock
	handlers   map[string]cloudformation.ResourceHandler
	roles      cloudformation.ExecutionRoles
	recorder   apievents.Recorder
	jobs       *scheduler.Driver
	operations map[string]func(context.Context) (any, *awswire.Error)
}

func New(c Config) *Service {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, clock: c.Clock, handlers: maps.Clone(c.Handlers), roles: c.Roles, recorder: c.Recorder, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, requestJobs{s})
	register(s, "CreateResource", s.create)
	register(s, "UpdateResource", s.update)
	register(s, "DeleteResource", s.delete)
	register(s, "GetResource", s.get)
	register(s, "ListResources", s.list)
	register(s, "GetResourceRequestStatus", s.status)
	register(s, "ListResourceRequests", s.requests)
	register(s, "CancelResourceRequest", s.cancel)
	return s
}

// SetHandlers completes assembly before attaching the shared driver or serving requests.
func (s *Service) SetHandlers(v map[string]cloudformation.ResourceHandler) {
	s.handlers = maps.Clone(v)
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	fn := s.operations[string(d.Operation.Name)]
	if fn == nil {
		return nil, failure("UnsupportedActionException", "Cloud Control operation is not implemented.")
	}
	return fn(awsapi.WithDecodedRequest(ctx, d))
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("GeneralServiceException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("cloudcontrol")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func register[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("GeneralServiceException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		if err = s.authorize(ctx, action); err != nil {
			rejected := wireError(err)
			if e := s.record(ctx, action, in, nil, rejected); e != nil {
				return nil, wireError(e)
			}
			return nil, rejected
		}
		out, err := fn(ctx, in)
		var rejected *awswire.Error
		if err != nil {
			rejected = wireError(err)
		}
		if rejected != nil || !mutationAction(action) {
			if e := s.record(ctx, action, in, out, rejected); e != nil {
				return nil, wireError(e)
			}
		}
		if rejected != nil {
			return nil, rejected
		}
		s.jobs.Wake()
		return out, nil
	}
}
func (s *Service) authorize(ctx context.Context, action string) error {
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "cloudformation:" + action, ResourceARN: "*", EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}
func (s *Service) roleContext(ctx context.Context, source, role string) (context.Context, error) {
	if role == "" {
		return awsctx.WithViaService(ctx, "cloudformation.amazonaws.com"), nil
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role, Context: map[string][]string{"iam:PassedToService": {"cloudformation.amazonaws.com"}}, EvaluationTime: &now}); denied != nil {
		return nil, denied
	}
	if s.roles == nil {
		return nil, failure("InvalidCredentialsException", "Cloud Control execution-role authority is unavailable.")
	}
	if err := s.roles.Validate(ctx, source, role); err != nil {
		return nil, err
	}
	return s.roles.Context(ctx, source, role)
}
func (s *Service) handler(name, version string) (cloudformation.ResourceHandler, cloudformation.ResourceReader, error) {
	if version != "" {
		return nil, nil, failure("UnsupportedActionException", "Private resource type versions are not implemented.")
	}
	h := s.handlers[name]
	reader, ok := h.(cloudformation.ResourceReader)
	if !ok {
		// TODO: Comeback implement authoritative readers and lifecycle adapters
		// for remaining registry resource types, private extensions and hooks.
		return nil, nil, failure("UnsupportedActionException", "Cloud Control resource type is not implemented: "+name)
	}
	return h, reader, nil
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown Cloud Control operation.")
	}
	return failure("ValidationException", err.Error())
}
func (s *Service) record(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("cloudcontrol")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List")}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	m := awsctx.FromContext(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, At: s.clock.Now()}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.record(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func mutationAction(action string) bool {
	return action == "CreateResource" || action == "UpdateResource" || action == "DeleteResource" || action == "CancelResourceRequest"
}
func (s *Service) recordMutation(ctx context.Context, event *api.ProgressEvent) error {
	d, ok := awsapi.FromContext(ctx)
	if !ok {
		return nil
	}
	var out any
	action := string(d.Operation.Name)
	switch action {
	case "CreateResource":
		out = &api.CreateResourceOutput{ProgressEvent: event}
	case "UpdateResource":
		out = &api.UpdateResourceOutput{ProgressEvent: event}
	case "DeleteResource":
		out = &api.DeleteResourceOutput{ProgressEvent: event}
	case "CancelResourceRequest":
		out = &api.CancelResourceRequestOutput{ProgressEvent: event}
	}
	return s.record(ctx, action, d.Input, out, nil)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, Account: m.AccountID, Region: m.Region}
}
func text[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func failure(code, message string) *awswire.Error {
	status := 400
	switch code {
	case "ResourceNotFoundException", "RequestTokenNotFoundException":
		status = 404
	case "GeneralServiceException":
		status = 500
	case "AccessDeniedException":
		status = 403
	case "ConcurrentOperationException", "ResourceConflictException":
		status = 409
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	if errors.Is(err, cloudformation.ErrCreateOnly) {
		return failure("NotUpdatableException", err.Error())
	}
	return failure("ValidationException", err.Error())
}
func active(status string) bool {
	return status == "PENDING" || status == "IN_PROGRESS" || status == "CANCEL_IN_PROGRESS"
}
