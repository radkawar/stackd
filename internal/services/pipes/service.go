package pipes

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	api "stackd/internal/awsapi/pipes"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"sync"
)

type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Sources      Sources
	KafkaSources KafkaSources
	Targets      Targets
	Metrics      MetricPublisher
	Keys         Keys
	Diagnostics  Diagnostics
}
type Service struct {
	repository    Repository
	authorizer    authorization.Authorizer
	recorder      apievents.Recorder
	clock         clock.Clock
	sources       Sources
	kafkaSources  KafkaSources
	kafkaMu       sync.Mutex
	kafka         map[string]KafkaConsumer
	targets       Targets
	metrics       MetricPublisher
	keys          Keys
	diagnostics   Diagnostics
	jobs          *scheduler.Driver
	operations    map[string]func(context.Context) (any, *awswire.Error)
	lifetime      context.Context
	cancel        context.CancelFunc
	subscriptions map[[2]string]pipeSubscription
	effectsMu     sync.Mutex
	effects       map[string]pipeEffect
	effectsDone   sync.WaitGroup
}

func NewWithConfig(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	s := &Service{
		repository:    c.Repository,
		authorizer:    c.Authorizer,
		recorder:      c.Recorder,
		clock:         c.Clock,
		sources:       c.Sources,
		kafkaSources:  c.KafkaSources,
		kafka:         map[string]KafkaConsumer{},
		targets:       c.Targets,
		metrics:       c.Metrics,
		keys:          c.Keys,
		diagnostics:   c.Diagnostics,
		operations:    map[string]func(context.Context) (any, *awswire.Error){},
		lifetime:      lifetime,
		cancel:        cancel,
		subscriptions: map[[2]string]pipeSubscription{},
		effects:       map[string]pipeEffect{},
	}
	s.jobs = scheduler.New(c.Clock, pipeJobs{s})
	registerControls(s)
	return s
}
func (s *Service) JobDriver() *scheduler.Driver {
	return s.jobs
}
func (s *Service) Start() {
	s.jobs.Start()
}
func (s *Service) Close() error {
	s.cancel()
	s.jobs.Close()
	s.effectsDone.Wait()
	for _, sub := range s.subscriptions {
		sub.cancel()
	}
	var err error
	for _, consumer := range s.kafka {
		err = errors.Join(err, consumer.Close())
	}
	return err
}
func (s *Service) Operations() []string {
	v := make([]string, 0, len(s.operations))
	for k := range s.operations {
		v = append(v, k)
	}
	slices.Sort(v)
	return v
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Expose-Headers", exposedHeaders)
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalException", "Missing generated request", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("pipes")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	f, ok := s.operations[string(d.Operation.Name)]
	if !ok {
		return nil, unsupported("Unknown Pipes operation")
	}
	return f(ctx)
}
func register[I, O any](s *Service, action string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalException", "Missing generated input", 500)
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(t Transaction) error {
			var e error
			out, e = f(t.Context(), t, in)
			if e != nil {
				return e
			}
			return s.recordCall(t.Context(), action, in, out, nil)
		})
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
	m, _ := awscatalog.LookupService("pipes")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (*Service) RequestError(_ string, e error) *awswire.Error {
	return failure("ValidationException", e.Error(), 400)
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(m string) *awswire.Error {
	return failure("ValidationException", m, 400)
}
func unsupported(m string) *awswire.Error {
	return failure("NotImplementedException", m, 501)
}
func wireError(e error) *awswire.Error {
	if e == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(e, &w) {
		return w
	}
	if errors.Is(e, ErrNotFound) {
		return failure("NotFoundException", "Pipe does not exist.", 404)
	}
	return failure("InternalException", e.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func (s *Service) authorize(ctx context.Context, p PipeRecord, action string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range p.Tags {
		conditions["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	now := s.clock.Now()
	resource := p.Key.ARN()
	if action == "ListPipes" {
		resource = "*"
	}
	returnWire := s.authorizer.Authorize(ctx, authorization.Request{
		Action:         "pipes:" + action,
		ResourceARN:    resource,
		Context:        conditions,
		ContextTypes:   map[string]string{"aws:TagKeys": "stringList"},
		EvaluationTime: &now,
	})
	if returnWire != nil {
		return returnWire
	}
	return nil
}
func (s *Service) load(ctx context.Context, r Reader, name, action string) (PipeRecord, error) {
	k := Key{scopeFor(ctx), name}
	p, e := r.Pipe(k)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return p, e
	}
	if rejected := s.authorize(ctx, PipeRecord{Key: k, Tags: p.Tags}, action, nil); rejected != nil {
		return p, rejected
	}
	if e == nil && (action == "DescribePipe" || action == "UpdatePipe") {
		return s.open(ctx, p)
	}
	return p, e
}
func (s *Service) passRole(ctx context.Context, p PipeRecord) error {
	now := s.clock.Now()
	w := s.authorizer.Authorize(ctx, authorization.Request{
		Action:         "iam:PassRole",
		ResourceARN:    p.RoleARN,
		EvaluationTime: &now,
		Context:        map[string][]string{"iam:PassedToService": {"pipes.amazonaws.com"}, "iam:AssociatedResourceArn": {p.Key.ARN()}},
	})
	if w != nil {
		return w
	}
	return nil
}
