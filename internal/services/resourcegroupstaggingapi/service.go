package resourcegroupstaggingapi

import (
	"context"
	"crypto/rand"
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
)

// Policies reads Organizations' committed effective tag policy, not attachments.
type Policies interface {
	EffectiveTagPolicy(context.Context) (string, error)
}

type Config struct {
	Repository Repository
	Resources  Resources
	Policies   Policies
	Governance Governance
	Reports    Reports
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
}
type Service struct {
	repository Repository
	resources  Resources
	policies   Policies
	governance Governance
	reports    Reports
	jobs       *scheduler.Driver
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	tokenKey   [32]byte
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
	s := &Service{repository: c.Repository, resources: c.Resources, policies: c.Policies, governance: c.Governance, reports: c.Reports, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	_, _ = rand.Read(s.tokenKey[:])
	register(s, "GetResources", s.getResources)
	register(s, "GetTagKeys", s.getTagKeys)
	register(s, "GetTagValues", s.getTagValues)
	register(s, "TagResources", s.tagResources)
	register(s, "UntagResources", s.untagResources)
	register(s, "GetComplianceSummary", s.getComplianceSummary)
	register(s, "ListRequiredTags", s.listRequiredTags)
	register(s, "DescribeReportCreation", s.describeReportCreation)
	registerReportStart(s)
	s.jobs = scheduler.New(c.Clock, reportJobs{s})
	return s
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
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
	model, _ := awscatalog.LookupService("resourcegroupstaggingapi")
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
	rejected := failure("NotImplementedException", "Resource Groups Tagging API operation is not implemented: "+action)
	rejected.StatusCode = http.StatusNotImplemented
	if err := s.authorize(ctx, action, nil, nil); err != nil {
		rejected = wireError(err)
	}
	if err := s.RecordRequestError(ctx, request, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServiceException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err == nil {
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
func (s *Service) authorize(ctx context.Context, action string, tags map[string]string, keys []string) error {
	conditions := map[string][]string{}
	if keys != nil {
		conditions["aws:TagKeys"] = keys
	}
	for key, value := range tags {
		conditions["aws:RequestTag/"+key] = []string{value}
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "tag:" + action, ResourceARN: "*", Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("resourcegroupstaggingapi")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: action != "TagResources" && action != "UntagResources" && action != "StartReportCreation"}
	call, err := projection.Call(model, operation, in, out, rejected)
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
		return failure("UnknownOperationException", "Unknown Resource Groups Tagging API operation.")
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if validation.TypeMismatch {
			return failure("SerializationException", validation.Error())
		}
		return failure("ValidationException", validation.Error())
	}
	return failure("InvalidParameterException", err.Error())
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServiceException" {
		status = http.StatusInternalServerError
	}
	if code == "AccessDeniedException" {
		status = http.StatusForbidden
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return &awswire.Error{Code: "InternalServiceException", Message: "Unable to access resource tagging state.", StatusCode: http.StatusInternalServerError, Cause: err}
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func boolean[T ~bool](v *T) bool   { return v != nil && bool(*v) }
func invalid(message string) error { return failure("InvalidParameterException", message) }
