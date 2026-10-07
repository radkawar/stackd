package guardduty

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
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type ServiceLinkedRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

type Config struct {
	Repository             Repository
	Authorizer             authorization.Authorizer
	Recorder               apievents.Recorder
	Clock                  clock.Clock
	Roles                  ServiceLinkedRoles
	Findings               FindingPublisher
	IPLists                IPListSource
	PublishingDestinations PublishingDestinationSink
	AuditJournal           KubernetesAuditJournal
}
type Service struct {
	repository      Repository
	authorizer      authorization.Authorizer
	recorder        apievents.Recorder
	clock           clock.Clock
	roles           ServiceLinkedRoles
	findings        FindingPublisher
	ipLists         IPListSource
	destinationSink PublishingDestinationSink
	auditJournal    KubernetesAuditJournal
	jobs            *scheduler.Driver
	operations      map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, roles: c.Roles, findings: c.Findings, ipLists: c.IPLists, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.destinationSink = c.PublishingDestinations
	s.auditJournal = c.AuditJournal
	s.jobs = scheduler.New(c.Clock, serviceJobs{s})
	registerDetectors(s)
	registerFindings(s)
	registerFilters(s)
	registerTags(s)
	registerIPLists(s)
	registerPublishingDestinations(s)
	return s
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Missing generated request binding", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("guardduty")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	// TODO: Comeback implement remaining detection sources/protection, organization
	// membership, entity sets and investigation
	// owners. Operation registration must never imply these effects have happened.
	rejected := invalid("This GuardDuty operation is not implemented")
	if err := s.RecordRequestError(ctx, d, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, name string, f func(Transaction, *I) (*O, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated input", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = f(tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), name, in, out, nil)
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
		if err := s.recordCall(completion, name, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func (*Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, err := api.NewInput(string(op.Name))
	if err != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("guardduty")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("guardduty")
	op, ok := model.Operation(name)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "Describe")}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func (s *Service) authorize(ctx context.Context, action, resource string, tags, requested map[string]string, keys []string) error {
	if resource == "" {
		resource = "*"
	}
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range requested {
		conditions["aws:RequestTag/"+k] = []string{v}
	}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	now := s.clock.Now()
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: "guardduty:" + action, ResourceARN: resource, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}
func (s *Service) loadDetector(r Reader, id, action string) (Detector, error) {
	sc := scopeFor(r.Context())
	v, err := r.Detector(sc, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if e := s.authorize(r.Context(), action, detectorARN(sc, id), v.Tags, nil, nil); e != nil {
		return v, e
	}
	if err != nil {
		return v, invalid("The request is rejected because the input detectorId is not owned by the current account.")
	}
	if err := checkCloudFormationOwnership(r.Context(), v.CFNOwnership); err != nil {
		return v, err
	}
	return v, nil
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func detectorARN(sc Scope, id string) string {
	return "arn:" + sc.Partition + ":guardduty:" + sc.Region + ":" + sc.AccountID + ":detector/" + id
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error { return failure("BadRequestException", message, 400) }
func wireError(err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return invalid("The requested resource does not exist")
	}
	return failure("InternalServerErrorException", err.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func text[T ~string](p **T, v string) { x := T(v); *p = &x }
func boolean[T ~bool](p **T, v bool)  { x := T(v); *p = &x }
