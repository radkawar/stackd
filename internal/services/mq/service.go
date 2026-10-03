package mq

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
)

type Config struct {
	Repository         Repository
	Authorizer         authorization.Authorizer
	Recorder           apievents.Recorder
	Clock              clock.Clock
	Runtime            Runtime
	Logs               LogDelivery
	Metrics            MetricPublisher
	ServiceLinkedRoles ServiceLinkedRoles
}
type Service struct {
	repository         Repository
	authorizer         authorization.Authorizer
	recorder           apievents.Recorder
	clock              clock.Clock
	runtime            Runtime
	logs               LogDelivery
	metrics            MetricPublisher
	serviceLinkedRoles ServiceLinkedRoles
	jobs               *scheduler.Driver
	operations         map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, logs: c.Logs, metrics: c.Metrics, serviceLinkedRoles: c.ServiceLinkedRoles, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, brokerJobs{s})
	registerBrokers(s)
	registerConfigurations(s)
	registerUsers(s)
	registerCatalog(s)
	return s
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		if name == "Promote" {
			// Authorized rejection is not support for replicated promotion.
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, _ := awscatalog.LookupService("mq")
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &m, failure("InternalServerErrorException", "Missing generated request", 500))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.RESTJSONError(w, r, &m, e)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(m, d.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &m, wireError(err))
		return
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

// TODO: Comeback implement private VPC/ENI attachment, standby and cluster brokers,
// managed storage KMS, automatic upgrades and replication through their real owners.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	e := invalid("This Amazon MQ operation is not implemented")
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, name string, f func(context.Context, Transaction, *I) (*O, error)) {
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
		err = s.repository.Attempt(ctx, func(t Transaction) error {
			var e error
			out, e = f(t.Context(), t, in)
			if e != nil {
				return e
			}
			return s.recordCall(t.Context(), name, in, out, nil)
		})
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		e := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		var dependency interface{ RecordRejection(context.Context) error }
		if errors.As(err, &dependency) {
			if err := dependency.RecordRejection(completion); err != nil {
				return nil, wireError(err)
			}
		}
		if err = s.recordCall(completion, name, in, nil, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error {
	var validation *awsapi.ValidationError
	if errors.As(e, &validation) && validation.Path == "MaxResults" {
		return invalidAttribute("maxResults", e.Error())
	}
	return invalid(e.Error())
}
func (*Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, e := api.NewInput(string(op.Name))
	if e != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("mq")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("mq")
	op, ok := m.Operation(name)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Describe") || strings.HasPrefix(name, "List")}
	call, e := projection.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	// Never retain broker passwords in the management journal, including malformed requests.
	var request map[string]any
	if len(call.RequestParameters) > 0 {
		if e = json.Unmarshal(call.RequestParameters, &request); e != nil {
			return e
		}
		redactPasswords(request)
		call.RequestParameters, e = json.Marshal(request)
		if e != nil {
			return e
		}
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func redactPasswords(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if strings.EqualFold(k, "password") {
				x[k] = "HIDDEN_DUE_TO_SECURITY_REASONS"
			} else {
				redactPasswords(v)
			}
		}
	case []any:
		for _, v := range x {
			redactPasswords(v)
		}
	}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error { return failure("BadRequestException", message, 400) }
func invalidAttribute(attribute, message string) *awswire.Error {
	e := invalid(message)
	raw, _ := json.Marshal(attribute)
	e.Details = map[string]json.RawMessage{"errorAttribute": raw}
	return e
}
func notFound(attribute, message string) *awswire.Error {
	e := failure("NotFoundException", message, 404)
	e.Cause = ErrNotFound
	if attribute != "" {
		raw, _ := json.Marshal(attribute)
		e.Details = map[string]json.RawMessage{"errorAttribute": raw}
	}
	return e
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, ErrNotFound) {
		// TODO: Comeback calibrate user and broker configuration-reference error attributes.
		return notFound("", "Resource was not found")
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
func tagMap[M ~map[K]V, K ~string, V ~string](p *M, v map[string]string) {
	*p = make(M, len(v))
	for k, x := range v {
		(*p)[K(k)] = V(x)
	}
}
func stringList[S ~[]E, E ~string](p *S, v []string) {
	*p = make(S, len(v))
	for i, x := range v {
		(*p)[i] = E(x)
	}
}
