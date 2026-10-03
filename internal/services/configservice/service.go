package configservice

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strconv"
	"strings"
)

type Config struct {
	Repository Repository
	Resources  Resources
	Effects    Effects
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
}
type Service struct {
	repository Repository
	resources  Resources
	effects    Effects
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
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
	s := &Service{repository: c.Repository, resources: c.Resources, effects: c.Effects, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerControls(s)
	registerHistory(s)
	registerRules(s)
	registerAggregations(s)
	registerTags(s)
	s.jobs = scheduler.New(c.Clock, configJobs{s})
	return s
}
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) wake(context.Context) {
	if s.jobs != nil {
		s.jobs.Wake()
	}
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServiceException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("configservice")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	action := string(request.Operation.Name)
	if fn, ok := s.operations[action]; ok {
		return fn(ctx)
	}
	// TODO: Comeback implement the remaining generated AWS Config operations;
	// unsupported conformance packs, remediation, organization and proactive
	// evaluation controls must not acknowledge effects that have not occurred.
	rejected := failure("NotImplementedException", "AWS Config operation is not implemented: "+action)
	rejected.StatusCode = http.StatusNotImplemented
	if err := s.authorize(ctx, action); err != nil {
		rejected = wireError(err)
	}
	if err := s.RecordRequestError(ctx, request, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	registerExternal(s, action, func(ctx context.Context, in *I) (out *O, err error) {
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var callErr error
			out, callErr = fn(tx, in)
			if callErr != nil {
				return callErr
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		return
	})
}

// registerExternal is for controls requiring preflight owner effects outside a
// Config transaction. Their callback commits both accepted intent and API fact.
func registerExternal[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServiceException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		out, err := fn(ctx, in)
		if err == nil {
			s.wake(ctx)
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
}
func (s *Service) authorize(ctx context.Context, action string) error {
	return s.authorizeResource(ctx, action, "*")
}

// Resource associations are defined per action, not by operation-name prefix:
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html
func (s *Service) authorizeResource(ctx context.Context, action, arn string) error {
	if arn == "*" {
		return s.authorizeResourceTags(ctx, action, arn, nil)
	}
	return s.repository.View(ctx, func(r Reader) error {
		tags, err := r.Tags(scopeFor(r.Context()), arn)
		if err != nil {
			return err
		}
		return s.authorizeResourceTags(r.Context(), action, arn, tags)
	})
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("configservice")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "BatchGet") || strings.HasPrefix(action, "Select")}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, At: s.clock.Now()}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown AWS Config operation.")
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && validation.TypeMismatch {
		return failure("SerializationException", validation.Error())
	}
	return failure("ValidationException", err.Error())
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServiceException" {
		status = 500
	}
	if code == "AccessDeniedException" {
		status = 403
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
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
	return &awswire.Error{Code: "InternalServiceException", Message: "Unable to access AWS Config state.", StatusCode: 500, Cause: err}
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func boolean[T ~bool](v *T) bool { return v != nil && bool(*v) }
func sequenceID(v int64) string  { return strconv.FormatInt(v, 10) }
func scopedContext(ctx context.Context, scope Scope) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = scope.Partition, scope.AccountID, scope.Region
	return awsctx.WithMetadata(ctx, m)
}
