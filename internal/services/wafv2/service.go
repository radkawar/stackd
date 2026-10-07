package wafv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

const regional = "REGIONAL"

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	// Resources resolves protected resource incarnations from their owners.
	Resources ProtectedResources
	// Metrics publishes AWS/WAFV2 metrics for rules with CloudWatch metrics enabled.
	Metrics MetricPublisher
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	resources  ProtectedResources
	metrics    MetricPublisher
	rates      *rateTracker
	jobs       *scheduler.Driver
	operations map[string]func(context.Context) (any, *awswire.Error)
	patterns   sync.Map
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, resources: c.Resources, metrics: c.Metrics, rates: newRateTracker(), operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, metricJobs{s})
	registerWebACLs(s)
	registerIPSets(s)
	registerTags(s)
	registerAssociations(s)
	registerObservations(s)
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

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
		awswire.JSONError(w, r, failure("WAFInternalErrorException", "Missing generated request", 500))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	m, _ := awscatalog.LookupService("wafv2")
	body, err := awsapi.EncodeResponse(m, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// ExecuteCommand implements the regional web ACL, IP set, association and
// observation controls. Rule groups, regex pattern sets, managed rule groups,
// logging, permission policies, API keys and CloudFront scope have no owner
// here and fail explicitly rather than storing inert configuration.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	e := failure("WAFInvalidOperationException", "This AWS WAF operation is not implemented by stackd", 400)
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}

func register[I, O any](s *Service, name string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("WAFInternalErrorException", "Missing generated input", 500)
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(t Transaction) error {
			var e error
			if out, e = f(t.Context(), t, in); e != nil {
				return e
			}
			return s.recordCall(t.Context(), name, in, out, nil)
		})
		if e == nil {
			return out, nil
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
func (*Service) RequestError(_ string, e error) *awswire.Error {
	return invalidParameter("", "", e.Error())
}
func (*Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, e := api.NewInput(string(op.Name))
	if e != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("wafv2")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("wafv2")
	op, ok := m.Operation(name)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") || name == "CheckCapacity"}
	call, e := p.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}

// authorize evaluates one IAM action ("service:Action") on one resource.
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
	e := s.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: arn, EvaluationTime: &now, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}})
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

// requireRegional admits the REGIONAL scope only: CLOUDFRONT web ACLs protect
// CloudFront distributions, which have no owner in this process.
func requireRegional(v *api.Scope) error {
	switch value(v) {
	case regional:
		return nil
	case "CLOUDFRONT":
		return invalidParameter("SCOPE_VALUE", "CLOUDFRONT", "CLOUDFRONT scope requires Amazon CloudFront distributions, which are not implemented; use REGIONAL")
	default:
		return invalidParameter("SCOPE_VALUE", value(v), "Scope must be REGIONAL or CLOUDFRONT")
	}
}

func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

// invalidParameter reports WAFInvalidParameterException with its modeled
// Field, Parameter and Reason members.
func invalidParameter(field, parameter, reason string) *awswire.Error {
	e := failure("WAFInvalidParameterException", reason, 400)
	e.Details = map[string]json.RawMessage{}
	for k, v := range map[string]string{"Field": field, "Parameter": parameter, "Reason": reason} {
		if v != "" {
			raw, _ := json.Marshal(v)
			e.Details[k] = raw
		}
	}
	return e
}
func nonexistent(message string) *awswire.Error {
	return failure("WAFNonexistentItemException", message, 400)
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
		return nonexistent("AWS WAF couldn’t perform the operation because your resource doesn't exist.")
	}
	return failure("WAFInternalErrorException", err.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
