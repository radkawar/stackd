// Package eventbridge implements regional event buses and retained target delivery.
package eventbridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

// Delivery runs outside the source transaction. The adapter authenticates the
// retained target role or service principal and invokes the actual destination.
type Delivery interface {
	Send(context.Context, DeliveryRequest) *awswire.Error
}
type DeliveryRequest struct {
	Delivery   DeliveryRecord
	Event      EventRecord
	Attributes map[string]string
}

// Payload renders the admitted event unless the target captured projected input.
// Bus forwarding consumes Event directly and never round-trips its wire JSON.
func (r DeliveryRequest) Payload() (string, error) {
	if r.Delivery.HasInput {
		return r.Delivery.Input, nil
	}
	return eventBody(r.Event)
}

// RuleRoles validates the role that PutRule admits. Target roles are instead
// resolved at execution, after admission has checked the caller's PassRole.
type RuleRoles interface {
	ValidateRuleRole(context.Context, string, RuleKey) *awswire.Error
}
type Events interface {
	AppendEventBridgeAccepted(context.Context, journal.Envelope, journal.EventBridgeAccepted) error
}
type Config struct {
	Repository        Repository
	Authorizer        authorization.Authorizer
	PolicyBinder      authorization.PolicyBinder
	Accounts          Accounts
	Clock             clock.Clock
	Delivery          Delivery
	Roles             RuleRoles
	Keys              ArchiveKeys
	BusKeys           BusKeys
	Metrics           MetricPublisher
	Events            Events
	APIEvents         apievents.Recorder
	ConnectionSecrets ConnectionSecrets
	HTTPClient        *http.Client
}
type Service struct {
	repository          Repository
	authorizer          authorization.Authorizer
	binder              authorization.PolicyBinder
	accounts            Accounts
	clock               clock.Clock
	delivery            Delivery
	roles               RuleRoles
	keys                ArchiveKeys
	busKeys             BusKeys
	busCache            busKeyCache
	metrics             MetricPublisher
	events              Events
	apiEvents           apievents.Recorder
	connectionSecrets   ConnectionSecrets
	httpClient          *http.Client
	connectionTokens    connectionTokenCache
	apiDestinationCalls apiDestinationCalls
	jobs                *scheduler.Driver
	operations          map[string]func(context.Context) (any, *awswire.Error)
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
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, accounts: c.Accounts, clock: c.Clock, delivery: c.Delivery, roles: c.Roles, keys: c.Keys, metrics: c.Metrics, events: c.Events, apiEvents: c.APIEvents, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.busKeys = c.BusKeys
	s.connectionSecrets = c.ConnectionSecrets
	s.httpClient = c.HTTPClient
	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}
	s.jobs = scheduler.New(c.Clock, archiveExpirationJobs{s}, archiveMigrationJobs{s}, scheduledRuleJobs{s}, deliveryJobs{s}, replayJobs{s}, replayExpirationJobs{s}, metricJobs{s}, connectionJobs{s})
	s.registerBuses()
	s.registerRules()
	s.registerTargets()
	s.registerEvents()
	s.registerTags()
	s.registerPermissions()
	s.registerArchives()
	s.registerReplays()
	s.registerConnections()
	s.registerAPIDestinations()
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for op := range s.operations {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error {
	// Cancel job contexts before HTTP work so shutdown cannot consume a retry.
	s.jobs.Close()
	s.closeAPIDestinations()
	s.busCache.close()
	return nil
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSEvents.")
	service, _ := awscatalog.LookupService("eventbridge")
	op, _ := service.Operation(action)
	decoded, _ := awsapi.FromContext(r.Context())
	decoded.Operation = op
	out, err := s.ExecuteCommand(r.Context(), decoded)
	if err != nil {
		awswire.JSONError(w, r, err)
		return
	}
	body, encodeErr := awsapi.EncodeResponse(service, op, out)
	if encodeErr != nil {
		awswire.JSONError(w, r, failure("InternalException", "Unable to encode EventBridge response.", 500))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement EventBridge partner events, endpoints, logging and remaining target services.
		return nil, unsupported("Unsupported EventBridge operation: " + action)
	}
	return fn(ctx)
}

// RequestError owns modeled validation errors for gateway and standalone callers.
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested EventBridge operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}

func register[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			rejected := failure("InternalException", "Missing generated request binding.", 500)
			if err := s.recordCall(ctx, action, nil, nil, rejected); err != nil {
				return nil, wireError(err)
			}
			return nil, rejected
		}
		return fn(ctx, in)
	}
}
func failure(code, message string, status ...int) *awswire.Error {
	n := 400
	if len(status) > 0 {
		n = status[0]
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: n}
}
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested resource does not exist.")
	}
	return failure("InternalException", "Unable to access EventBridge state.", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func str[T ~string](v string) *T { p := T(v); return &p }
func ptr[T any](v T) *T          { return &v }
func compare(a, b string) int    { return strings.Compare(a, b) }
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
