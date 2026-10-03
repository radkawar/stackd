package signer

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/signer"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
	"sync"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Objects    Objects
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	objects    Objects
	flights    sync.Map
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, objects: c.Objects, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerProfiles(s)
	registerJobs(s)
	registerRevocation(s)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for n := range s.operations {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServiceErrorException", "Missing generated request", 500))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	m, _ := awscatalog.LookupService("signer")
	body, err := awsapi.EncodeResponse(m, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// TODO: Comeback support cross-account profile grants, non-Lambda platforms and
// SignPayload only when their current resource/cryptographic owners exist.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	e := invalid("This AWS Signer operation is not implemented")
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, name string, f func(context.Context, Transaction, *I) (*O, error)) {
	registerDetached(s, name, func(ctx context.Context, in *I) (*O, error) {
		var out *O
		e := s.repository.Attempt(ctx, func(t Transaction) error {
			var e error
			out, e = f(t.Context(), t, in)
			if e != nil {
				return e
			}
			return s.recordCall(t.Context(), name, in, out, nil)
		})
		return out, e
	}, true)
}
func registerDetached[I, O any](s *Service, name string, f func(context.Context, *I) (*O, error), recorded bool) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServiceErrorException", "Missing generated input", 500)
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		out, e := f(ctx, in)
		if e == nil {
			if !recorded {
				e = s.recordCall(ctx, name, in, out, nil)
			}
			if e == nil {
				return out, nil
			}
		}
		rejected := wireError(e)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e = s.recordCall(completion, name, in, nil, rejected); e != nil {
			return nil, wireError(e)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func (*Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, e := api.NewInput(string(op.Name))
	if e != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("signer")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("signer")
	op, ok := m.Operation(name)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "Describe")}
	call, e := p.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags map[string]string, conditions map[string][]string) error {
	if arn == "" {
		arn = "*"
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	e := s.authorizer.Authorize(ctx, authorization.Request{Action: "signer:" + action, ResourceARN: arn, EvaluationTime: &now, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}})
	if e == nil {
		return nil
	}
	if e.StatusCode == 403 {
		return failure("AccessDeniedException", e.Message, 403)
	}
	return e
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error { return failure("ValidationException", message, 400) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Signing resource does not exist", 404)
	}
	return failure("InternalServiceErrorException", err.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func text[T ~string](p **T, v string) { x := T(v); *p = &x }
func tags[M ~map[K]V, K ~string, V ~string](p *M, v map[string]string) {
	*p = make(M, len(v))
	for k, x := range v {
		(*p)[K(k)] = V(x)
	}
}
