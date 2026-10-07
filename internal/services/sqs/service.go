// Package sqs implements scoped queues and offline message delivery.
package sqs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type operation func(*http.Request) (any, *awswire.Error)

// Service owns queues independently of other emulator instances. All mutable
// state is protected by mu; long polling and HTTP writes never hold it.
type Service struct {
	repository Repository
	reader     Reader
	command    *commandAudit
	stateErr   error
	removed    map[queueKey]bool
	runtimes   map[string]*queueRuntime
	keyWork    *keyWork

	mu             sync.Mutex
	kms            KMS
	authorizer     authorization.Authorizer
	journal        MessageJournal
	apiEvents      apievents.Recorder
	metrics        MetricPublisher
	tasks          map[string]*MoveTaskRecord
	jobs           *scheduler.Driver
	jobsChanged    bool
	polls          sync.WaitGroup
	effects        sync.WaitGroup
	closed         bool
	nextMove       uint64
	lifetime       context.Context
	stop           context.CancelFunc
	queues         map[queueKey]*queue
	deleted        map[queueKey]time.Time
	operations     map[string]operation
	clock          clock.Clock
	publicEndpoint string
	endpointDomain string
	// transactionTime is sampled once per repository callback while mu is held.
	transactionTime time.Time
	tokenKey        [32]byte
	// TODO: Comeback implement PostgreSQL SQS storage, journal remaining queue/message lifecycle transitions and persist remaining job attempts; accepted sends already commit with the shared journal.
}

// New creates a standalone SQS provider with empty state.
func New() *Service {
	return NewWithConfig(Config{})
}

// Config selects storage, authorization, encryption and modeled service time.
// Nil dependencies select isolated memory, root authorization and real time;
// KMS-backed queues require an explicitly supplied KMS implementation.
type Config struct {
	Repository     Repository
	KMS            KMS
	Authorizer     authorization.Authorizer
	Clock          clock.Clock
	Journal        MessageJournal
	APIEvents      apievents.Recorder
	Metrics        MetricPublisher
	PublicEndpoint string
	EndpointDomain string
}

// MessageJournal appends accepted sends in the queue's resource transaction.
// The built-in provider receives the coordinated instance journal.
type MessageJournal interface {
	AppendSQSMessageAccepted(context.Context, journal.Envelope, journal.SQSMessageAccepted) error
}

// NewWithConfig creates an isolated SQS provider. Its clock governs both
// transactional deadlines and long-poll/redrive timers.
func NewWithConfig(config Config) *Service {
	if config.Repository == nil {
		config.Repository = NewMemoryRepository(nil)
	}
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if config.Authorizer == nil {
		config.Authorizer = authorization.NewWithClock(nil, nil, config.Clock)
	}
	s := &Service{queues: make(map[queueKey]*queue), deleted: make(map[queueKey]time.Time), operations: make(map[string]operation), clock: config.Clock}
	_, _ = rand.Read(s.tokenKey[:])
	s.repository = config.Repository
	s.kms = config.KMS
	s.runtimes = make(map[string]*queueRuntime)
	s.lifetime, s.stop = context.WithCancel(context.Background())
	s.authorizer = config.Authorizer
	s.journal = config.Journal
	s.apiEvents = config.APIEvents
	s.metrics = config.Metrics
	s.publicEndpoint, s.endpointDomain = config.PublicEndpoint, config.EndpointDomain
	s.tasks = make(map[string]*MoveTaskRecord)
	s.jobs = scheduler.New(config.Clock, moveJobs{s}, metricJobs{s}, queueMetricJobs{s})
	s.registerPermissions()
	s.registerMoves()
	s.registerQueues()
	s.registerMessages()
	s.registerBatch()
	return s
}

// now supplies one consistent modeled timestamp within a repository callback.
// The caller holds mu and has initialized the working set through prepare.
func (s *Service) now() time.Time { return s.transactionTime }

// Operations reports actions with implemented behavior.
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// ServeHTTP consumes the AWS JSON 1.0 SQS protocol with generated contracts.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	result, err := s.dispatch(r, action)
	if err != nil {
		awswire.JSONError(w, r, err)
		return
	}
	service, _ := awscatalog.LookupService("sqs")
	op, _ := service.Operation(action)
	body, encodeErr := awsapi.EncodeResponse(service, op, result)
	if encodeErr != nil {
		awswire.JSONError(w, r, &awswire.Error{Code: "InternalError", Message: "Unable to serialize response.", StatusCode: 500})
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	r := (&http.Request{Header: http.Header{"X-Amz-Target": {"AmazonSQS." + action}}, Body: http.NoBody}).WithContext(ctx)
	return s.dispatch(r, action)
}

func (s *Service) dispatch(r *http.Request, action string) (any, *awswire.Error) {
	handler, ok := s.operations[action]
	if !ok {
		// The modeled operation list is generated; unknown future actions fail explicitly.
		return nil, failure("UnsupportedOperation", "Unsupported SQS operation: "+action)
	}
	return handler(r)
}

func register[I any, O any](s *Service, action string, locked bool, fn func(*http.Request, *I) (*O, *awswire.Error)) {
	s.operations[action] = func(r *http.Request) (result any, wireErr *awswire.Error) {
		audit := &commandAudit{action: action, final: true}
		defer s.completeCommand(r.Context(), audit, &wireErr)
		input, ok := awsapi.Input[I](r.Context())
		if !ok {
			body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			if err != nil {
				return nil, failure("InvalidParameterValue", "Unable to read request.")
			}
			decoded, err := api.DecodeRequest(action, awsapi.Request{JSON: body})
			if err != nil {
				return nil, failure("InvalidParameterValue", err.Error())
			}
			input, ok = decoded.Input.(*I)
			if !ok {
				return nil, &awswire.Error{Code: "InternalError", Message: "Invalid operation binding.", StatusCode: 500}
			}
		}
		audit.input = input
		if locked {
			var result *O
			err := s.authorizedUpdate(r, action, input, audit, func(r *http.Request) *awswire.Error {
				var err *awswire.Error
				result, err = fn(r, input)
				audit.output = result
				return err
			})
			return result, err
		}
		return fn(r, input)
	}
}

func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func ptr[T any](v T) *T        { return &v }
func str(v string) *api.String { return ptr(api.String(v)) }
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
