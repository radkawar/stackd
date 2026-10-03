package organizations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	orgapi "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type operation func(*http.Request, func(any) *awswire.Error) (any, *awswire.Error)

// Service owns independent Organizations state shared across regions.
type Service struct {
	mu                 sync.RWMutex
	storage            Storage
	authorizer         authorization.Authorizer
	operations         map[string]operation
	tokenKey           [32]byte
	clock              clock.Clock
	accountQuotas      *AccountQuotas
	accountProvisioner AccountProvisioner
	roleInspector      RoleInspector
	events             Events
	apiEvents          apievents.Recorder
	jobs               *scheduler.Driver
	// TODO: Comeback implement PostgreSQL Organizations/account storage, remaining resource events and durable job attempts with SQLite state.
}

// New constructs an empty Organizations service.
func New() *Service {
	return NewWithStorage(NewMemoryStorage(nil))
}

// NewWithStorage uses replaceable typed partition storage. The default
// authorizer permits verified account roots subject to the applicable SCPs.
func NewWithStorage(storage Storage) *Service {
	return NewWithConfig(Config{Storage: storage})
}

// Config binds Organizations timestamps and policy evaluation to service time.
type Config struct {
	Storage       Storage
	Clock         clock.Clock
	AccountQuotas *AccountQuotas
	Events        Events
	APIEvents     apievents.Recorder
}

func NewWithConfig(config Config) *Service {
	storage, source := config.Storage, config.Clock
	if source == nil {
		source = clock.Real{}
	}
	if storage == nil {
		storage = NewMemoryStorage(nil)
	}
	s := &Service{storage: storage, operations: make(map[string]operation), clock: source, accountQuotas: config.AccountQuotas, events: config.Events, apiEvents: config.APIEvents}
	s.authorizer = authorization.NewWithClock(nil, organizationControlSource{s}, source)
	s.jobs = scheduler.New(source, accountCreationJobs{s}, handshakeJobs{s}, effectivePolicyJobs{s})
	_, _ = rand.Read(s.tokenKey[:])
	s.registerOrganizationOperations()
	s.registerHandshakeOperations()
	s.registerUnitOperations()
	s.registerAccountOperations()
	s.registerPolicyOperations()
	s.registerResourcePolicyOperations()
	s.registerTagOperations()
	s.registerServiceAccessOperations()
	return s
}

// SetAuthorizer configures IAM, session and SCP evaluation before serving.
func (s *Service) SetAuthorizer(authorizer authorization.Authorizer) {
	if authorizer == nil {
		authorizer = authorization.NewWithClock(nil, organizationControlSource{s}, s.clock)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizer = authorizer
}

// Operations returns the sorted action names implemented by this provider.
func (s *Service) Operations() []string {
	actions := make([]string, 0, len(s.operations))
	for action := range s.operations {
		actions = append(actions, action)
	}
	slices.Sort(actions)
	return actions
}

// ServeHTTP processes an AWS JSON 1.1 Organizations request.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action, ok := strings.CutPrefix(r.Header.Get("X-Amz-Target"), "AWSOrganizationsV20161128.")
	if !ok {
		awswire.JSONError(w, r, failure("UnknownOperationException", "An AWS Organizations target is required."))
		return
	}
	var body []byte
	_, err := s.dispatch(r, action, func(result any) *awswire.Error {
		var err error
		body, err = orgapi.EncodeResponse(action, result)
		if err != nil {
			return &awswire.Error{Code: "ServiceException", Message: "Unable to serialize response.", StatusCode: http.StatusInternalServerError}
		}
		return nil
	})
	if err != nil {
		awswire.JSONError(w, r, err)
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// ExecuteCommand runs an admitted generated request through Organizations' authority.
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	action := string(decoded.Operation.Name)
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	// Existing operation handlers borrow the request's context and target only.
	// No HTTP transport, body decoding, or response encoding runs for commands.
	r := (&http.Request{Header: http.Header{"X-Amz-Target": {"AWSOrganizationsV20161128." + action}}}).WithContext(ctx)
	return s.dispatch(r, action, nil)
}

func (s *Service) dispatch(r *http.Request, action string, prepareResponse func(any) *awswire.Error) (any, *awswire.Error) {
	handler, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement remaining management-policy report APIs, GovCloud accounts, and responsibility transfers.
		return nil, failure("UnknownOperationException", "Unsupported Organizations operation: "+action)
	}
	return handler(r, prepareResponse)
}

func (s *operationState) organizationFor(r *http.Request, managementOnly bool) (*orgState, *awswire.Error) {
	accountID := awsctx.FromContext(r.Context()).AccountID
	orgID, ok := s.memberships[accountID]
	if !ok {
		return nil, failure("AWSOrganizationsNotInUseException", "This account is not a member of an organization.")
	}
	o := s.orgs[orgID]
	if managementOnly && o.organization.MasterAccountID != accountID {
		action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSOrganizationsV20161128.")
		if o.accounts[accountID].State == "ACTIVE" && (len(o.delegates[accountID]) > 0 && delegatedReadAllowed(action) || o.resourcePolicy.ID != "" && delegationActionAllowed(action)) {
			return o, nil
		}
		return nil, failure("AccessDeniedException", "This operation requires the organization's management account.")
	}
	return o, nil
}

func failure(code, message string) *awswire.Error {
	err := &awswire.Error{Code: code, Message: message, StatusCode: http.StatusBadRequest}
	if code == "HandshakeConstraintViolationException" || code == "ConstraintViolationException" || code == "InvalidInputException" {
		reason, _, _ := strings.Cut(message, ":")
		isEnum := strings.Contains(reason, "_")
		for _, r := range reason {
			if (r < 'A' || r > 'Z') && r != '_' {
				isEnum = false
				break
			}
		}
		if isEnum {
			err.Reason = reason
		}
	}
	return err
}

func identifier(prefix string, bytes int) string {
	data := make([]byte, bytes)
	_, _ = rand.Read(data)
	return prefix + hex.EncodeToString(data)
}

func (s *operationState) timestamp() float64 { return float64(s.instant.UnixMilli()) / 1000 }
