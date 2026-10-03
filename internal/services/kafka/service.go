package kafka

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
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Runtime    Runtime
	Secrets    Secrets
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	runtime    Runtime
	secrets    Secrets
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, secrets: c.Secrets, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, clusterJobs{s})
	registerClusters(s)
	registerConfigurations(s)
	registerResources(s)
	return s
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string {
	v := make([]string, 0, len(s.operations))
	for k := range s.operations {
		v = append(v, k)
	}
	slices.Sort(v)
	return v
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Missing generated request", 500))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	m, _ := awscatalog.LookupService("kafka")
	body, err := awsapi.EncodeResponse(m, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// TODO: Comeback implement MSK serverless, managed VPC/network enforcement,
// IAM/mTLS data authentication, managed storage encryption, monitoring sinks,
// replication, multi-VPC connectivity and mutable fleet topology with real owners.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	w := unsupported("This MSK operation is not implemented")
	if e := s.RecordRequestError(ctx, d, w); e != nil {
		return nil, wireError(e)
	}
	return nil, w
}
func register[I, O any](s *Service, action string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated input", 500)
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		ctx, e = s.prepare(ctx, action, in)
		var out *O
		if e == nil {
			e = s.repository.Attempt(ctx, func(t Transaction) error {
				var err error
				out, err = f(t.Context(), t, in)
				if err != nil {
					return err
				}
				return s.recordCall(t.Context(), action, in, out, nil)
			})
		}
		if e == nil {
			s.jobs.Wake()
			return out, nil
		}
		w := wireError(e)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e = s.recordCall(completion, action, in, nil, w); e != nil {
			return nil, wireError(e)
		}
		return nil, w
	}
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (s *Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, e := api.NewInput(string(op.Name))
	if e != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("kafka")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(m string) *awswire.Error     { return failure("BadRequestException", m, 400) }
func unsupported(m string) *awswire.Error { return invalid(m) }
func conflict(m string) *awswire.Error    { return failure("ConflictException", m, 409) }
func wireError(e error) *awswire.Error {
	if e == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(e, &w) {
		return w
	}
	if errors.Is(e, ErrNotFound) {
		return failure("NotFoundException", "MSK resource does not exist", 404)
	}
	return failure("InternalServerErrorException", e.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

// The official model names primitive types privately; these setters infer them.
func text[T ~string](p **T, v string)                     { x := T(v); *p = &x }
func number[T ~int32 | ~int64 | ~float64](p **T, v int64) { x := T(v); *p = &x }
func boolean[T ~bool](p **T, v bool)                      { x := T(v); *p = &x }
func stringList[S ~[]E, E ~string](p *S, v []string) {
	*p = make(S, 0, len(v))
	for _, s := range v {
		*p = append(*p, E(s))
	}
}
func tagMap[M ~map[K]V, K ~string, V ~string](p *M, v map[string]string) {
	*p = make(M, len(v))
	for k, s := range v {
		(*p)[K(k)] = V(s)
	}
}
func plainTags[M ~map[K]V, K ~string, V ~string](v M) map[string]string {
	out := make(map[string]string, len(v))
	for k, s := range v {
		out[string(k)] = string(s)
	}
	return out
}
func plainList[S ~[]E, E ~string](v S) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return out
}

func parameterError(err *awswire.Error, name string) *awswire.Error {
	field, _ := json.Marshal(name)
	err.Details = map[string]json.RawMessage{"invalidParameter": field}
	return err
}
