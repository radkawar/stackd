// Package kms implements local KMS keys and cryptographic operations.
package kms

import (
	"context"
	"crypto/rand"
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
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type operation func(context.Context, any, func(any) *awswire.Error) (any, *awswire.Error)

// Service owns the keys and aliases of an isolated local KMS instance.
type Service struct {
	mu              sync.Mutex
	stores          map[scope]*keyStore
	baselines       map[scope]*keyStore
	keySets         map[keySetReference]*KeySetRecord
	storage         Storage
	transaction     Reader
	storageErr      error
	operations      map[string]operation
	tokenKey        [32]byte
	now             func() time.Time
	transactionTime time.Time
	authorizer      authorization.Authorizer
	regions         RegionAccess
	roles           ServiceRoles
	jobs            *scheduler.Driver
	apiEvents       apievents.Recorder
	// TODO: Comeback implement PostgreSQL KMS storage and commit material/lifecycle events and durable scheduler attempts with the shared transaction domain.
}

// New constructs an empty service. Key material is generated with crypto/rand.
func New() *Service {
	return NewWithAuthorization(authorization.New(nil, nil))
}

// NewWithAuthorization applies the shared IAM and organization authorization
// boundary to every public KMS operation and internal cryptographic request.
func NewWithAuthorization(authorizer authorization.Authorizer) *Service {
	return NewWithStorage(NewMemoryStorage(nil), authorizer)
}

// NewWithStorage assembles a KMS provider with replaceable transactional storage.
// A nil backend selects isolated memory storage; nil authorization allows roots only.
func NewWithStorage(storage Storage, authorizer authorization.Authorizer) *Service {
	return NewWithConfig(Config{Storage: storage, Authorizer: authorizer})
}

// Config selects KMS state, authorization and the service lifecycle clock.
type Config struct {
	Storage    Storage
	Authorizer authorization.Authorizer
	Clock      clock.Clock
	Regions    RegionAccess
	Roles      ServiceRoles
	APIEvents  apievents.Recorder
}

func NewWithConfig(config Config) *Service {
	storage, authorizer := config.Storage, config.Authorizer
	source := config.Clock
	if source == nil {
		source = clock.Real{}
	}
	if storage == nil {
		storage = NewMemoryStorage(nil)
	}
	if authorizer == nil {
		authorizer = authorization.NewWithClock(nil, nil, source)
	}
	s := &Service{storage: storage, operations: make(map[string]operation), now: source.Now, authorizer: authorizer, regions: config.Regions, roles: config.Roles, apiEvents: config.APIEvents}
	s.jobs = scheduler.New(source, lifecycleJobs{s})
	_, _ = rand.Read(s.tokenKey[:])
	s.registerKeys()
	s.registerAliases()
	s.registerTags()
	s.registerCrypto()
	s.registerPolicies()
	s.registerGrants()
	s.registerRotation()
	s.registerImports()
	s.registerMultiRegion()
	return s
}

func (s *Service) currentTime() time.Time {
	if s.transaction != nil {
		return s.transactionTime
	}
	return s.now()
}

// Operations reports only operations with implemented behavior.
func (s *Service) Operations() []string {
	names := make([]string, 0, len(s.operations))
	for name := range s.operations {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ServeHTTP processes the generated AWS JSON 1.1 KMS contract.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	_, implemented := s.operations[name]
	if !ok || !implemented {
		awswire.JSONError(w, r, failure("UnknownOperationException", "Unsupported KMS operation: "+name))
		return
	}
	decoded, bound := awsapi.FromContext(r.Context())
	if !bound {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 {
			awswire.JSONError(w, r, s.requestError(r.Context(), name, failure("ValidationException", "Invalid request body.")))
			return
		}
		decoded, err = kmsapi.DecodeRequest(name, awsapi.Request{JSON: body})
		if err != nil {
			awswire.JSONError(w, r, s.requestError(r.Context(), name, failure("ValidationException", err.Error())))
			return
		}
	}
	var body []byte
	_, wire := s.dispatch(r.Context(), decoded, func(out any) *awswire.Error {
		var err error
		body, err = kmsapi.EncodeResponse(name, out)
		if err != nil {
			return failure("KMSInternalException", "Unable to serialize KMS response.")
		}
		return nil
	})
	if wire != nil {
		awswire.JSONError(w, r, wire)
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	return s.dispatch(ctx, decoded, nil)
}

func (s *Service) dispatch(ctx context.Context, decoded awsapi.DecodedRequest, prepare func(any) *awswire.Error) (any, *awswire.Error) {
	name := string(decoded.Operation.Name)
	handler, ok := s.operations[name]
	if !ok {
		// TODO: Comeback implement SM2 keys and key agreement, custom-store keys, attestation recipients, and remaining KMS APIs.
		return nil, failure("UnknownOperationException", "Unsupported KMS operation: "+name)
	}
	return handler(awsapi.WithDecodedRequest(ctx, decoded), decoded.Input, prepare)
}

func register[I, O any](s *Service, name string, fn func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context, value any, prepare func(any) *awswire.Error) (any, *awswire.Error) {
		input, ok := value.(*I)
		if !ok {
			return nil, s.requestError(ctx, name, failure("KMSInternalException", "Generated input contract mismatch."))
		}
		ctx = withAction(ctx, name, nil)
		output, err := s.auditCommand(ctx, name, input, func(ctx context.Context) (any, *awswire.Error) {
			switch name {
			case "ListKeys", "ListAliases", "GenerateRandom":
				if err := s.authorize(ctx, "*", "", false, nil); err != nil {
					return nil, err
				}
			}
			out, err := fn(ctx, input)
			if err != nil {
				return nil, err
			}
			if prepare != nil {
				if err := prepare(out); err != nil {
					return nil, err
				}
			}
			return out, nil
		})
		if err != nil {
			return nil, err
		}
		// Commands own their transaction. Wake only after its commit;
		// recovery scans also discover keys created through service consumers.
		s.jobs.Wake()
		return output, nil
	}
}

func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "KMSInternalException" {
		status = http.StatusInternalServerError
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func ptr[T any](v T) *T { return &v }
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func isTrue[T ~bool](v *T) bool { return v != nil && bool(*v) }
