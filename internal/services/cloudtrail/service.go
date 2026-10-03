// Package cloudtrail owns management history, configured trails and retained log delivery.
package cloudtrail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"stackd/storage/memory"
)

// EventLog reads the one immutable source journal; trails retain only event IDs.
type EventLog interface {
	LookupAPICalls(context.Context, journal.APICallQuery) (journal.APICallPage, error)
	ReadAPICalls(context.Context, []string) ([]journal.Event, error)
}

// LogDestination makes independent S3 requests for destination preflight and
// delivery. No CloudTrail transaction spans those effects. The adapter supplies
// the trusted trail principal and the originating API event's causal identity.
// Validation returns the canonical encryption key ARN, or empty for SSE-S3.
// Writes receive the trail's current canonical key ARN for that delivery attempt.
type LogDestination interface {
	Validate(context.Context, TrailRecord, string) (string, *awswire.Error)
	Write(context.Context, DeliveryRecord, string, []byte, string) *awswire.Error
}

// CloudWatchLogsDestination preflights and writes individual CloudTrail records
// outside trail transactions. The adapter supplies role authorization and service
// delivery timestamps, not the source eventTime.
type CloudWatchLogsDestination interface {
	Validate(context.Context, TrailRecord, string) *awswire.Error
	Write(context.Context, DeliveryRecord, []json.RawMessage, string) *awswire.Error
}

// NotificationDestination publishes native validation messages and log-object
// notifications through SNS. SNS owns policy enforcement and subscriber fanout.
// Both calls run outside CloudTrail transactions.
type NotificationDestination interface {
	Validate(context.Context, TrailRecord, string) *awswire.Error
	Write(context.Context, DeliveryRecord, string, string) *awswire.Error
}

type Config struct {
	Repository        Repository
	Journal           EventLog
	Destination       LogDestination
	LogsDestination   CloudWatchLogsDestination
	Notifications     NotificationDestination
	Organizations     OrganizationView
	OrganizationRoles OrganizationRoles
	APIEvents         apievents.Recorder
	Authorizer        authorization.Authorizer
	Clock             clock.Clock
}

type Service struct {
	repository        Repository
	journal           EventLog
	destination       LogDestination
	logsDestination   CloudWatchLogsDestination
	notifications     NotificationDestination
	organizations     OrganizationView
	organizationRoles OrganizationRoles
	apiEvents         apievents.Recorder
	authorizer        authorization.Authorizer
	clock             clock.Clock
	jobs              *scheduler.Driver
	operations        map[string]func(context.Context, any) (any, *awswire.Error)
}

func New(config Config) *Service {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if config.Repository == nil || config.Journal == nil {
		domain := memory.NewDomain()
		if config.Repository == nil {
			config.Repository = NewMemoryRepository(domain)
		}
		if config.Journal == nil {
			config.Journal = journal.NewMemory(domain)
		}
	}
	if config.Authorizer == nil {
		config.Authorizer = authorization.NewWithClock(nil, nil, config.Clock)
	}
	s := &Service{repository: config.Repository, journal: config.Journal, destination: config.Destination, logsDestination: config.LogsDestination, notifications: config.Notifications, apiEvents: config.APIEvents, authorizer: config.Authorizer, clock: config.Clock, operations: map[string]func(context.Context, any) (any, *awswire.Error){}}
	s.organizations = config.Organizations
	s.organizationRoles = config.OrganizationRoles
	s.jobs = scheduler.New(config.Clock, deliveryJobs{s})
	register(s, "LookupEvents", s.lookup)
	s.registerTrails()
	return s
}

func register[I, O any](s *Service, name string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, in any) (any, *awswire.Error) { return fn(ctx, in.(*I)) }
}
func (s *Service) Operations() []string {
	operations := make([]string, 0, len(s.operations))
	for name := range s.operations {
		operations = append(operations, name)
	}
	slices.Sort(operations)
	return operations
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoded, bound := awsapi.FromContext(r.Context())
	if !bound {
		prefix, action, ok := awswire.JSONTarget(r.Header.Get("X-Amz-Target"))
		if !ok || prefix != "CloudTrail_20131101" {
			awswire.JSONError(w, r, failure("UnknownOperationException", "Target does not match CloudTrail."))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 {
			awswire.JSONError(w, r, failure("InvalidParameterException", "Invalid request body."))
			return
		}
		decoded, err = api.DecodeRequest(action, awsapi.Request{JSON: body})
		if err != nil {
			wire := s.RequestError(action, err)
			if err := s.RecordRequestError(r.Context(), decoded, wire); err != nil {
				wire = storageFailure()
			}
			awswire.JSONError(w, r, wire)
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), decoded))
	}
	action := string(decoded.Operation.Name)
	out, wire := s.ExecuteCommand(r.Context(), decoded)
	if wire != nil {
		awswire.JSONError(w, r, wire)
		return
	}
	body, err := api.EncodeResponse(action, out)
	if err != nil {
		awswire.JSONError(w, r, storageFailure())
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	handler, ok := s.operations[action]
	if !ok {
		// CloudTrail Lake is intentionally excluded, not a deferred implementation.
		// TODO: Comeback implement Insights and remaining non-Lake CloudTrail operations.
		return nil, unsupported("Unsupported CloudTrail operation: " + action)
	}
	return s.execute(ctx, decoded, handler)
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested CloudTrail operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		code := "InvalidParameterException"
		switch {
		case strings.Contains(invalid.Path, "EventSelectors"):
			code = "InvalidEventSelectorsException"
		case strings.Contains(invalid.Path, "MaxResults"):
			code = "InvalidMaxResultsException"
		case strings.Contains(invalid.Path, "LookupAttributes"):
			code = "InvalidLookupAttributesException"
		case strings.Contains(invalid.Path, "EventCategory"):
			code = "InvalidEventCategoryException"
		case strings.Contains(invalid.Path, "NextToken"):
			code = "InvalidNextTokenException"
		case strings.Contains(invalid.Path, "StartTime"), strings.Contains(invalid.Path, "EndTime"):
			code = "InvalidTimeRangeException"
		}
		return failure(code, invalid.Error())
	}
	return failure("InvalidParameterException", "Invalid request body.")
}
func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
func storageFailure() *awswire.Error {
	return &awswire.Error{Code: "InternalError", Message: "Unable to access CloudTrail state.", StatusCode: 500}
}
func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "UnsupportedOperationException", Message: message, StatusCode: 501}
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("TrailNotFoundException", "The requested trail does not exist.")
	}
	return storageFailure()
}
