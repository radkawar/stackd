package cloudformation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
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
)

const Namespace = "http://cloudformation.amazonaws.com/doc/2010-05-15/"

// TemplateSource reads customer template objects through the S3 owner.
type TemplateSource interface {
	ReadTemplate(context.Context, string) (string, error)
}

// ParameterSource resolves ordinary SSM parameter values under current authority.
type ParameterSource interface {
	ResolveParameter(context.Context, string) (string, error)
}

// AvailabilityZoneSource borrows EC2's account-scoped inventory and default
// subnet filtering under the caller's current authority.
type AvailabilityZoneSource interface {
	CloudFormationAvailabilityZones(context.Context, string) ([]string, error)
}

type Config struct {
	Repository        Repository
	Authorizer        authorization.Authorizer
	Clock             clock.Clock
	Handlers          map[string]ResourceHandler
	Roles             ExecutionRoles
	Recorder          apievents.Recorder
	Templates         TemplateSource
	Parameters        ParameterSource
	AvailabilityZones AvailabilityZoneSource
}

type Service struct {
	repository        Repository
	authorizer        authorization.Authorizer
	clock             clock.Clock
	handlers          map[string]ResourceHandler
	roles             ExecutionRoles
	recorder          apievents.Recorder
	templates         TemplateSource
	parameters        ParameterSource
	availabilityZones AvailabilityZoneSource
	jobs              *scheduler.Driver
	operations        map[string]func(context.Context) (any, *awswire.Error)
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
	s.templates, s.parameters = c.Templates, c.Parameters
	s.availabilityZones = c.AvailabilityZones
	s.jobs = scheduler.New(c.Clock, deploymentJobs{s})
	s.registerStacks()
	s.registerChangeSets()
	s.registerReads()
	return s
}

// SetHandlers completes explicit assembly before the service starts accepting
// requests or its driver is attached. There is no global resource registry.
func (s *Service) SetHandlers(v map[string]ResourceHandler) { s.handlers = maps.Clone(v) }

// SetTemplateSources completes explicit assembly before accepting requests.
func (s *Service) SetTemplateSources(templates TemplateSource, parameters ParameterSource) {
	s.templates, s.parameters = templates, parameters
}
func (s *Service) SetAvailabilityZoneSource(source AvailabilityZoneSource) {
	s.availabilityZones = source
}
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	fn := s.operations[string(d.Operation.Name)]
	if fn == nil {
		// TODO: Comeback implement StackSets, registry/extensions, transforms,
		// drift detection, stack refactoring and resource import with real owners.
		return nil, failure("NotImplementedException", "CloudFormation operation is not implemented: "+string(d.Operation.Name), 501)
	}
	return fn(awsapi.WithDecodedRequest(ctx, d))
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.QueryError(w, r, Namespace, rejected)
		return
	}
	model, _ := awscatalog.LookupService("cloudformation")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.QueryError(w, r, Namespace, wireError(err))
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, string(d.Operation.Name), body)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "Unknown CloudFormation operation.")
	}
	return failure("ValidationError", err.Error())
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated request binding.", 500)
		}
		var out *O
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		d, _ := awsapi.FromContext(ctx)
		err = s.repository.Update(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), d, in, out, nil)
		})
		if err != nil {
			rejected := wireError(err)
			if e := s.recordCall(ctx, d, in, nil, rejected); e != nil {
				return nil, wireError(e)
			}
			return nil, rejected
		}
		s.jobs.Wake()
		return out, nil
	}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status ...int) *awswire.Error {
	n := 400
	if len(status) > 0 {
		n = status[0]
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: n}
}
func invalid(message string) error { return failure("ValidationError", message) }
func wireError(err error) *awswire.Error {
	var w *awswire.Error
	if errors.As(err, &w) {
		return w
	}
	return failure("ValidationError", err.Error())
}
func text[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func truth[T ~bool](p *T) bool { return p != nil && bool(*p) }
func (s *Service) authorize(r Reader, action string, stack StackRecord) error {
	arn := stack.ID
	if arn == "" {
		arn = "*"
	}
	values := map[string][]string{}
	for k, v := range stack.Tags {
		values["aws:ResourceTag/"+k] = []string{v}
	}
	if stack.RoleARN != "" {
		values["cloudformation:RoleArn"] = []string{stack.RoleARN}
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "cloudformation:" + action, ResourceARN: arn, Context: values, EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}

// A supplied role governs this request; otherwise the stack's retained role
// remains effective. Keep this projection separate from persisted stack state.
func (s *Service) authorizeRole(r Reader, action string, stack StackRecord, requested string) error {
	if requested != "" {
		stack.RoleARN = requested
	}
	return s.authorize(r, action, stack)
}
func findStack(r Reader, name string) (StackRecord, error) {
	scope := scopeFor(r.Context())
	if strings.HasPrefix(name, "arn:") {
		v, e := r.Stack(name)
		if e == nil && v.Scope == scope {
			return v, nil
		}
		if e != nil && !errors.Is(e, ErrNotFound) {
			return v, e
		}
		return StackRecord{}, invalid("Stack with id " + name + " does not exist")
	}
	rows, e := r.Stacks(scope)
	if e != nil {
		return StackRecord{}, e
	}
	for _, v := range rows {
		if v.Name == name && v.Deleted == nil {
			return v, nil
		}
	}
	return StackRecord{}, invalid("Stack with id " + name + " does not exist")
}
func supportedInput(input any, allowed ...string) error {
	v := reflect.ValueOf(input).Elem()
	t := v.Type()
	for i := range v.NumField() {
		if !v.Field(i).IsZero() && !slices.Contains(allowed, t.Field(i).Name) {
			// TODO: Comeback add stack policies, rollback alarms, notifications,
			// timeout and deployment strategies through genuine owners.
			return failure("NotImplementedException", "CloudFormation does not implement "+t.Field(i).Name+".", 501)
		}
	}
	return nil
}
func (s *Service) role(r Reader, stackID, requested, previous string) (string, error) {
	role := requested
	if role == "" {
		return previous, nil
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "iam:PassRole", ResourceARN: role, Context: map[string][]string{"iam:PassedToService": {"cloudformation.amazonaws.com"}}, EvaluationTime: &now}); denied != nil {
		return "", denied
	}
	if s.roles == nil {
		return "", invalid("CloudFormation execution-role authority is unavailable")
	}
	if e := s.roles.Validate(r.Context(), stackID, role); e != nil {
		return "", e
	}
	return role, nil
}
func stackARN(scope Scope, name, id string) string {
	return fmt.Sprintf("arn:%s:cloudformation:%s:%s:stack/%s/%s", scope.Partition, scope.Region, scope.Account, name, id)
}
