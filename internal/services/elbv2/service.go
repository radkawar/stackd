package elbv2

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const Namespace = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Networks     NetworkAuthority
	Runtime      NativeRuntime
	Certificates CertificateSource
	Metrics      MetricPublisher
	DNS          DNSAuthority
}
type Service struct {
	repository   Repository
	authorizer   authorization.Authorizer
	recorder     apievents.Recorder
	clock        clock.Clock
	networks     NetworkAuthority
	certificates CertificateSource
	metrics      MetricPublisher
	runtime      *runtimeController
	dns          DNSAuthority
	dnsAttached  bool
	dnsRelease   func()
	operations   map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, networks: c.Networks, certificates: c.Certificates, metrics: c.Metrics, dns: c.DNS, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerLoadBalancers(s)
	registerTargetGroups(s)
	registerListeners(s)
	registerRules(s)
	registerTargets(s)
	registerTags(s)
	s.runtime = newRuntimeController(s, c)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for k := range s.operations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated request"))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.QueryError(w, r, Namespace, rejected)
		return
	}
	m, _ := awscatalog.LookupService("elbv2")
	body, e := awsapi.EncodeResponse(m, d.Operation, out)
	if e != nil {
		awswire.QueryError(w, r, Namespace, wireError(e))
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, string(d.Operation.Name), body)
}

// TODO: Comeback extend the modeled ALB kernel to the remaining ELB protocols,
// certificate/authentication sources, advanced routing attributes and consumers.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	w := unsupported("The requested Elastic Load Balancing operation is not supported")
	if e := s.RecordRequestError(ctx, d, w); e != nil {
		return nil, wireError(e)
	}
	return nil, w
}
func register[I, O any](s *Service, action string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated input")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = f(tx.Context(), tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if e == nil {
			s.wakeRuntime()
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
	m, _ := awscatalog.LookupService("elbv2")
	if awsapi.Decode(m, op, r, v) != nil {
		return nil
	}
	return v
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
func invalid(m string) *awswire.Error     { return failure("ValidationError", m) }
func unsupported(m string) *awswire.Error { return failure("UnsupportedOperation", m) }
func wireError(e error) *awswire.Error {
	if e == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(e, &w) {
		return w
	}
	return &awswire.Error{Code: "InternalFailure", Message: e.Error(), StatusCode: 500}
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
func plainList[S ~[]E, E ~string](v S) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return out
}
