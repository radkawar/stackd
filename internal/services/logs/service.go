package logs

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
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

// Events appends accepted source batches in the resource transaction. It is
// separate from CloudTrail API outcomes: PutLogEvents is not a management event.
type Events interface {
	AppendLogsBatchAccepted(context.Context, journal.Envelope, journal.LogsBatchAccepted) error
}

// MetricPublisher commits extracted samples in the source transaction; it does
// not impersonate the application or synthesize a PutMetricData API call.
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}

type Config struct {
	Repository    Repository
	Authorizer    authorization.Authorizer
	APIEvents     apievents.Recorder
	Events        Events
	Clock         clock.Clock
	Subscriptions SubscriptionDestination
	Metrics       MetricPublisher
}
type Service struct {
	repository    Repository
	authorizer    authorization.Authorizer
	apiEvents     apievents.Recorder
	events        Events
	clock         clock.Clock
	subscriptions SubscriptionDestination
	metrics       MetricPublisher
	jobs          *scheduler.Driver
	operations    map[string]func(context.Context, any) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, apiEvents: c.APIEvents, events: c.Events, clock: c.Clock, subscriptions: c.Subscriptions, metrics: c.Metrics, operations: map[string]func(context.Context, any) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, subscriptionJobs{s}, retentionJobs{s})
	register(s, "CreateLogGroup", s.createLogGroup)
	register(s, "DeleteLogGroup", s.deleteLogGroup)
	register(s, "DescribeLogGroups", s.describeLogGroups)
	register(s, "ListLogGroups", s.listLogGroups)
	register(s, "CreateLogStream", s.createLogStream)
	register(s, "DeleteLogStream", s.deleteLogStream)
	register(s, "DescribeLogStreams", s.describeLogStreams)
	register(s, "PutLogEvents", s.putLogEvents)
	register(s, "GetLogEvents", s.getLogEvents)
	register(s, "FilterLogEvents", s.filterLogEvents)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagLogGroup", s.tagLogGroup)
	register(s, "UntagLogGroup", s.untagLogGroup)
	register(s, "ListTagsLogGroup", s.listTagsLogGroup)
	register(s, "PutRetentionPolicy", s.putRetentionPolicy)
	register(s, "DeleteRetentionPolicy", s.deleteRetentionPolicy)
	register(s, "PutResourcePolicy", s.putResourcePolicy)
	register(s, "DescribeResourcePolicies", s.describeResourcePolicies)
	register(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	s.operations["PutSubscriptionFilter"] = func(ctx context.Context, in any) (any, *awswire.Error) {
		return s.putSubscriptionFilter(ctx, in.(*api.PutSubscriptionFilterRequest))
	}
	register(s, "DescribeSubscriptionFilters", s.describeSubscriptionFilters)
	register(s, "DeleteSubscriptionFilter", s.deleteSubscriptionFilter)
	s.operations["PutDestination"] = func(ctx context.Context, in any) (any, *awswire.Error) {
		return s.putDestination(ctx, in.(*api.PutDestinationRequest))
	}
	register(s, "PutDestinationPolicy", s.putDestinationPolicy)
	register(s, "DescribeDestinations", s.describeDestinations)
	register(s, "DeleteDestination", s.deleteDestination)
	register(s, "PutMetricFilter", s.putMetricFilter)
	register(s, "DescribeMetricFilters", s.describeMetricFilters)
	register(s, "DeleteMetricFilter", s.deleteMetricFilter)
	register(s, "TestMetricFilter", s.testMetricFilter)
	return s
}
func register[I, O any](s *Service, name string, fn func(Transaction, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, in any) (any, *awswire.Error) {
		var out *O
		err := s.update(ctx, func(tx Transaction) (any, *awswire.Error) {
			var wire *awswire.Error
			out, wire = fn(tx, in.(*I))
			return out, wire
		})
		return out, wireError(err)
	}
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for n := range s.operations {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, storageFailure())
		return
	}
	out, wire := s.ExecuteCommand(r.Context(), decoded)
	if wire != nil {
		awswire.JSONError(w, r, wire)
		return
	}
	body, err := api.EncodeResponse(string(decoded.Operation.Name), out)
	if err != nil {
		awswire.JSONError(w, r, storageFailure())
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Logs operation is not recognized.")
	}
	var v *awsapi.ValidationError
	if errors.As(err, &v) {
		rejected := invalid(v.Error())
		rejected.Cause = err
		return rejected
	}
	return invalid("Invalid request body.")
}
func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
func invalid(message string) *awswire.Error { return failure("InvalidParameterException", message) }
func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "UnsupportedOperationException", Message: message, StatusCode: 501}
}
func storageFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceUnavailableException", Message: "Unable to access CloudWatch Logs state.", StatusCode: 500}
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(err, &w) {
		return w
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The specified log group or log stream does not exist.")
	}
	return storageFailure()
}
func (s *Service) command(ctx context.Context, name string, in any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("logs")
	op, _ := model.Operation(name)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
}

// CreateLogGroup, CreateLogStream and PutLogEvents are the shared command boundary
// for the generated HTTP frontend and execution-role-authorized runtime capture.
func (s *Service) CreateLogGroup(ctx context.Context, in *api.CreateLogGroupRequest) (*api.CreateLogGroupOutput, *awswire.Error) {
	out, w := s.command(ctx, "CreateLogGroup", in)
	if w != nil {
		return nil, w
	}
	return out.(*api.CreateLogGroupOutput), nil
}
func (s *Service) CreateLogStream(ctx context.Context, in *api.CreateLogStreamRequest) (*api.CreateLogStreamOutput, *awswire.Error) {
	out, w := s.command(ctx, "CreateLogStream", in)
	if w != nil {
		return nil, w
	}
	return out.(*api.CreateLogStreamOutput), nil
}
func (s *Service) PutLogEvents(ctx context.Context, in *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error) {
	out, w := s.command(ctx, "PutLogEvents", in)
	if w != nil {
		return nil, w
	}
	return out.(*api.PutLogEventsResponse), nil
}
