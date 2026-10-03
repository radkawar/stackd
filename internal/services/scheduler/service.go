package scheduler

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	jobs "stackd/internal/scheduler"
)

type Delivery interface {
	ValidateTarget(context.Context, ScheduleKey, TargetRecord) *awswire.Error
	Send(context.Context, DeliveryRecord, string, bool) *awswire.Error
}

type Roles interface {
	ValidateRole(context.Context, ScheduleKey, string) *awswire.Error
}

type EncryptionKeys interface {
	Seal(context.Context, ScheduleKey, string, []byte) (ciphertext, dataKey []byte, keyARN string, rejected *awswire.Error)
	Open(context.Context, ScheduleKey, string, []byte, []byte) ([]byte, *awswire.Error)
}

type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Clock      clock.Clock
	Delivery   Delivery
	Roles      Roles
	Keys       EncryptionKeys
	Metrics    MetricPublisher
	APIEvents  apievents.Recorder
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	clock      clock.Clock
	delivery   Delivery
	roles      Roles
	keys       EncryptionKeys
	metrics    MetricPublisher
	apiEvents  apievents.Recorder
	jobs       *jobs.Driver
	operations map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{
		repository: c.Repository,
		authorizer: c.Authorizer,
		clock:      c.Clock,
		delivery:   c.Delivery,
		roles:      c.Roles,
		keys:       c.Keys,
		metrics:    c.Metrics,
		apiEvents:  c.APIEvents,
		operations: map[string]func(context.Context) (any, *awswire.Error){},
	}
	s.jobs = jobs.New(c.Clock, occurrenceJobs{s}, deliveryJobs{s})
	s.registerGroups()
	s.registerSchedules()
	s.registerTags()
	return s
}

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func (s *Service) JobDriver() *jobs.Driver {
	return s.jobs
}

func (s *Service) Close() error {
	s.jobs.Close()
	return nil
}

func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	fn, ok := s.operations[string(d.Operation.Name)]
	if !ok {
		return nil, unsupported("Scheduler operation is not implemented.")
	}
	return fn(ctx)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("scheduler")
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("ValidationException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, failure("InternalServerException", "Unable to encode response.", 500))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown Scheduler operation.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("ValidationException", invalid.Error())
	}
	return failure("ValidationException", "Invalid request.")
}

func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerException", "Missing generated request binding.", 500)
		}
		var out *O
		err := s.repository.Update(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err != nil {
			rejected := wireError(err)
			if e := s.recordCall(ctx, action, in, nil, rejected); e != nil {
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
	return Scope{
		m.Partition,
		m.AccountID,
		m.Region,
	}
}

func (s *Service) authorize(r Reader, action, arn string, tags map[string]string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(r.Context(), authorization.Request{
		Action:         "scheduler:" + action,
		ResourceARN:    arn,
		Context:        conditions,
		EvaluationTime: &now,
	}); rejected != nil {
		return rejected
	}
	return nil
}

func failure(code, message string, status ...int) *awswire.Error {
	n := 400
	if len(status) > 0 {
		n = status[0]
	}
	return &awswire.Error{
		Code:       code,
		Message:    message,
		StatusCode: n,
	}
}

func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}

func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			return failure("AccessDeniedException", e.Message, 403)
		}
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested resource does not exist.", 404)
	}
	return &awswire.Error{
		Code:       "InternalServerException",
		Message:    "Unable to access Scheduler state.",
		StatusCode: 500,
		Cause:      err,
	}
}

func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func groupName(v string) string {
	if v == "" {
		return "default"
	}
	return v
}

func optional[T ~string](v string, has bool) *T {
	if !has {
		return nil
	}
	return new(T(v))
}

func validName(v string) bool {
	return len(v) > 0 && len(v) <= 64 && strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") == ""
}
