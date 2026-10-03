package sns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// Delivery consumes an already projected native payload outside SNS state
// transactions. Its context carries the SNS service principal and source topic.
// A nil result error means target acceptance, not successful customer execution.
type Delivery interface {
	Send(ctx context.Context, protocol, endpoint string, message DeliveryMessage) DeliveryResult
}

// DeliveryResult preserves the actual target response for source-owned retry,
// completion and feedback decisions. Error is never inferred from log fields.
type DeliveryResult struct {
	Error            *awswire.Error
	StatusCode       int
	ProviderResponse string
}

type DeliveryMessage struct {
	Body                                       string
	MessageGroupID                             string
	MessageDeduplicationID                     string
	Attributes                                 api.MessageAttributeMap
	SubscriptionRoleARN                        string
	Type, MessageID, TopicARN, SubscriptionARN string
	ContentType                                string
	Raw                                        bool
	CaptureFeedback                            bool
}

// RoleValidator checks current SNS trust without creating credentials.
type RoleValidator interface {
	ValidateSubscriptionRole(context.Context, TopicKey, string) *awswire.Error
	ValidateFeedbackRole(context.Context, TopicKey, string) *awswire.Error
}

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	APIEvents    apievents.Recorder
	Roles        RoleValidator
	Clock        clock.Clock
	Delivery     Delivery
	Metrics      MetricPublisher
	Feedback     FeedbackPublisher
	Keys         DataKeys
	// PublicEndpoint is the trusted externally reachable instance origin used
	// for SNS public certificates and subscription URLs; never a request Host.
	PublicEndpoint string
}

type Service struct {
	repository     Repository
	authorizer     authorization.Authorizer
	binder         authorization.PolicyBinder
	apiEvents      apievents.Recorder
	roles          RoleValidator
	clock          clock.Clock
	delivery       Delivery
	metrics        MetricPublisher
	feedback       FeedbackPublisher
	keys           DataKeys
	keyMu          sync.Mutex
	keyCache       map[dataKeySlot]cachedDataKey
	publicEndpoint string
	jobs           *scheduler.Driver
	operations     map[string]func(context.Context) (any, *awswire.Error)
	signingMu      sync.Mutex
	signingKey     *rsa.PrivateKey
	signingRecord  SigningKeyRecord
}

// Native deletion propagation retained routable subscriptions across same-name
// recreation for the captured window. Five local minutes is a controllable
// propagation choice, not a measured AWS deletion deadline.
// TODO: Comeback calibrate SNS subscription deletion timing beyond the bounded native observations.
const topicSubscriptionDeletionDelay = 5 * time.Minute

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
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, apiEvents: c.APIEvents, clock: c.Clock, delivery: c.Delivery, metrics: c.Metrics, publicEndpoint: c.PublicEndpoint, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.roles = c.Roles
	s.feedback = c.Feedback
	s.keys, s.keyCache = c.Keys, make(map[dataKeySlot]cachedDataKey)
	s.jobs = scheduler.New(c.Clock, subscriptionDeletionJobs{s}, archiveExpirationJobs{s}, replayJobs{s}, deliveryJobs{s}, archiveMetricJobs{s}, metricJobs{s})
	s.registerTopics()
	s.registerTags()
	s.registerPermissions()
	s.registerSubscriptions()
	register(s, "Publish", s.Publish)
	register(s, "PublishBatch", s.publishBatch)
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
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error {
	s.jobs.Close()
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	for slot, key := range s.keyCache {
		clear(key.plaintext)
		delete(s.keyCache, slot)
	}
	return nil
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("sns")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, model.XMLNamespace, wireError(errors.New("missing SNS generated input")))
		return
	}
	action := string(decoded.Operation.Name)
	output, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.QueryError(w, r, model.XMLNamespace, rejected)
		return
	}
	response, err := awsapi.EncodeResponse(model, decoded.Operation, output)
	if err != nil {
		awswire.QueryError(w, r, model.XMLNamespace, wireError(err))
		return
	}
	awswire.WriteQueryBytes(w, r, model.XMLNamespace, action, response)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement mobile/SMS and data-protection commands with their real dependencies.
		return nil, unsupported("SNS operation is not implemented: " + action)
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalError", "Missing generated SNS request binding.", 500)
		}
		return fn(ctx, in)
	}
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "The requested SNS operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("InvalidParameter", invalid.Error())
	}
	return failure("InvalidParameter", "Invalid request body.")
}
func failure(code, message string, status ...int) *awswire.Error {
	n := 400
	model, _ := awscatalog.LookupService("sns")
	if shape, ok := model.ErrorShape(code); ok && shape.Error.HTTPStatus != 0 {
		n = shape.Error.HTTPStatus
	}
	if len(status) != 0 {
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
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("NotFound", "Topic does not exist")
	}
	return failure("InternalError", "Unable to access SNS state.", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func str[T ~string](v string) *T { p := T(v); return &p }
func ptr[T any](v T) *T          { return &v }
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
