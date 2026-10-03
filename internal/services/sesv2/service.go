package sesv2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	jobs "stackd/internal/scheduler"
	"strings"
)

type Config struct {
	Repository                       Repository
	Authorizer                       authorization.Authorizer
	APIEvents                        apievents.Recorder
	Clock                            clock.Clock
	CaptureDirectory, PublicEndpoint string
}
type Service struct {
	repository                       Repository
	authorizer                       authorization.Authorizer
	apiEvents                        apievents.Recorder
	clock                            clock.Clock
	captureDirectory, publicEndpoint string
	jobs                             *jobs.Driver
	operations                       map[string]func(context.Context) (any, *awswire.Error)
}

func NewWithConfig(c Config) *Service {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, apiEvents: c.APIEvents, clock: c.Clock, captureDirectory: c.CaptureDirectory, publicEndpoint: strings.TrimRight(c.PublicEndpoint, "/"), operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = jobs.New(c.Clock, captureJobs{s})
	s.registerControls()
	s.registerIdentityPolicies()
	s.registerSending()
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
func (s *Service) JobDriver() *jobs.Driver { return s.jobs }
func (s *Service) Close() error            { s.jobs.Close(); return nil }
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	fn, ok := s.operations[string(d.Operation.Name)]
	if !ok {
		// TODO: Comeback — SES suppression/contact lists, event destinations, delivery analytics, DKIM/DNS domains, custom MAIL FROM, dedicated IPs, tenants and outbound SMTP require their real owners.
		rejected := unsupported("SES operation is not implemented: " + string(d.Operation.Name))
		if e := s.RecordRequestError(ctx, d, rejected); e != nil {
			return nil, wireError(e)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("BadRequestException", "Missing generated request binding.", 400))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("sesv2")
	body, e := awsapi.EncodeResponse(model, d.Operation, out)
	if e != nil {
		awswire.JSONError(w, r, wireError(e))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (*Service) RequestError(_ string, e error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if errors.As(e, &invalid) {
		return bad(invalid.Error())
	}
	return bad("Invalid SES request.")
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	registerOperation(s, s.operations, action, fn, false)
}

func registerOperation[I, O any](s *Service, operations map[string]func(context.Context) (any, *awswire.Error), action string, fn func(Transaction, *I) (*O, error), classic bool) {
	errorFor := wireError
	if classic {
		errorFor = func(e error) *awswire.Error { return classicError(action, e) }
	}
	operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, bad("Missing generated request binding.")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, errorFor(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if e != nil {
			rejected := errorFor(e)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if e = s.recordCall(completion, action, in, nil, rejected); e != nil {
				return nil, errorFor(e)
			}
			return nil, rejected
		}
		s.jobs.Wake()
		return out, nil
	}
}
func (s *Service) authorize(r Reader, action, arn string, tags map[string]string, conditions map[string][]string) error {
	request := s.authorizationRequest(r, action, arn, tags, conditions)
	if rejected := s.authorizer.Authorize(r.Context(), request); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) authorizationRequest(r Reader, action, arn string, tags map[string]string, conditions map[string][]string) authorization.Request {
	conditions = maps.Clone(conditions)
	if conditions == nil {
		conditions = map[string][]string{}
	}
	conditions["ses:ApiVersion"] = []string{"2"}
	if isClassic(r.Context()) {
		conditions["ses:ApiVersion"] = []string{"1"}
		if d, ok := awsapi.FromContext(r.Context()); ok {
			action = string(d.Operation.Name)
		}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	return authorization.Request{Action: "ses:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) *awswire.Error { return failure("BadRequestException", message, 400) }
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}
func wireError(e error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(e, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message, 403)
		}
		return wire
	}
	if errors.Is(e, ErrNotFound) {
		return failure("NotFoundException", "The requested SES resource does not exist.", 404)
	}
	return &awswire.Error{Code: "InternalServiceErrorException", Message: "Unable to access SES state.", StatusCode: http.StatusInternalServerError, Cause: e}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func newID() (string, error) {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
