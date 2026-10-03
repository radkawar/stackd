package cloudwatch

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	APIEvents  apievents.Recorder
	Clock      clock.Clock
	Events     AlarmEventPublisher
	Actions    AlarmActionSender
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	apiEvents  apievents.Recorder
	clock      clock.Clock
	events     AlarmEventPublisher
	actions    AlarmActionSender
	jobs       *scheduler.Driver
	operations map[string]func(context.Context, any) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, apiEvents: c.APIEvents, clock: c.Clock, events: c.Events, actions: c.Actions, operations: map[string]func(context.Context, any) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, alarmEvaluationJobs{s}, alarmActionJobs{s})
	register(s, "PutMetricData", s.putMetricData)
	register(s, "GetMetricStatistics", s.getMetricStatistics)
	register(s, "GetMetricData", s.getMetricData)
	register(s, "ListMetrics", s.listMetrics)
	s.registerAlarms()
	s.registerDashboards()
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listResourceTags)
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

func register[I, O any](s *Service, name string, fn func(Transaction, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, input any) (any, *awswire.Error) {
		var output *O
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			var wire *awswire.Error
			output, wire = fn(tx, input.(*I))
			if wire != nil {
				return wire
			}
			decoded, _ := awsapi.FromContext(tx.Context())
			return s.record(tx.Context(), decoded, output, nil)
		})
		return output, wireError(err)
	}
}

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("cloudwatch")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		writeError(w, r, model, storageFailure())
		return
	}
	model.Protocol = decoded.Protocol
	output, wire := s.ExecuteCommand(r.Context(), decoded)
	if wire != nil {
		writeError(w, r, model, wire)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, output)
	if err != nil {
		writeError(w, r, model, storageFailure())
		return
	}
	if model.Protocol == awscatalog.AWSQuery {
		awswire.WriteQueryBytes(w, r, model.XMLNamespace, string(decoded.Operation.Name), response.Body)
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func writeError(w http.ResponseWriter, r *http.Request, model awscatalog.Service, failure *awswire.Error) {
	switch model.Protocol {
	case awscatalog.RPCV2CBOR:
		awswire.RPCV2Error(w, r, &model, failure)
	case awscatalog.AWSQuery:
		awswire.QueryError(w, r, model.XMLNamespace, failure)
	default:
		awswire.JSONError(w, r, failure)
	}
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	handler, ok := s.operations[string(decoded.Operation.Name)]
	if !ok {
		// TODO: Comeback implement remaining alarm engines, streams, Insights and CloudWatch control planes with their actual dependencies.
		return nil, unsupported("CloudWatch operation is not implemented: " + string(decoded.Operation.Name))
	}
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	if s.apiEvents != nil {
		var err error
		ctx, err = apievents.Reserve(ctx)
		if err != nil {
			return nil, storageFailure()
		}
	}
	output, wire := handler(ctx, decoded.Input)
	if wire != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.record(completion, decoded, nil, wire); err != nil {
			return nil, storageFailure()
		}
	}
	return output, wire
}

func (s *Service) RequestError(action string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "The requested CloudWatch operation is not recognized.")
	}
	var invalidInput *awsapi.ValidationError
	if errors.As(err, &invalidInput) {
		if action != "PutMetricData" && action != "GetMetricStatistics" && action != "ListMetrics" {
			return failure("ValidationError", invalidInput.Error())
		}
		if invalidInput.Constraint == "required" {
			return failure("MissingParameter", invalidInput.Error())
		}
		return invalid(invalidInput.Error())
	}
	return invalid("Invalid request body.")
}

func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	model, _ := awscatalog.LookupService("cloudwatch")
	if shape, ok := model.ErrorShape(code); ok && shape.Error.HTTPStatus != 0 {
		status = shape.Error.HTTPStatus
	} else if code == "AccessDenied" || code == "InvalidClientTokenId" {
		status = http.StatusForbidden
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func invalid(message string) *awswire.Error { return failure("InvalidParameterValue", message) }

func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "NotImplementedException", Message: message, StatusCode: http.StatusNotImplemented}
}

func storageFailure() *awswire.Error {
	return &awswire.Error{Code: "InternalServiceError", Message: "Unable to access CloudWatch state.", StatusCode: http.StatusInternalServerError}
}

func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return storageFailure()
}

// Publish admits service-generated metrics in the source's transaction. It is
// not a synthetic PutMetricData API call and does not require the originating
// application's identity to hold cloudwatch:PutMetricData.
// Retained observations keep their original timestamps; the public API's
// admission-age window does not apply to delayed source publication.
func (s *Service) Publish(ctx context.Context, namespace string, data []api.MetricDatum) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		return s.publish(tx, namespace, data, false)
	})
}
