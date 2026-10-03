package identitystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Clock      clock.Clock
	APIEvents  apievents.Recorder
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	clock      clock.Clock
	apiEvents  apievents.Recorder
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, clock: c.Clock, apiEvents: c.APIEvents, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.registerUsers()
	s.registerGroups()
	s.registerMemberships()
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for k := range s.operations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if fn, ok := s.operations[string(d.Operation.Name)]; ok {
		return fn(ctx)
	}
	return nil, unsupported("Identity Store operation is not implemented: " + string(d.Operation.Name))
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, bad("Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("identitystore")
	body, e := awsapi.EncodeResponse(model, d.Operation, out)
	if e != nil {
		awswire.JSONError(w, r, wireError(e))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (*Service) RequestError(_ string, e error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if errors.As(e, &invalid) {
		return bad(invalid.Error())
	}
	return bad("Invalid Identity Store request.")
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, bad("Missing generated request binding.")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), action, nil)
		})
		if e != nil {
			rejected := wireError(e)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if e := s.recordCall(completion, action, rejected); e != nil {
				return nil, wireError(e)
			}
			return nil, rejected
		}
		return out, nil
	}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}

// TODO: Comeback — legacy sso-directory action aliases and organization-member
// directory sharing require their native authority contracts; this owner is scoped.
func (s *Service) admit(r Reader, action, store, user, group, membership string) error {
	scope := scopeFor(r.Context())
	arn := "arn:" + scope.Partition + ":identitystore::" + scope.AccountID + ":identitystore/" + store
	now := s.clock.Now()
	authorize := func(resource string) error {
		if e := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "identitystore:" + action, ResourceARN: resource, ResourceAccountID: scope.AccountID, Context: map[string][]string{"identitystore:PrimaryRegion": {scope.Region}}, EvaluationTime: &now}); e != nil {
			return e
		}
		return nil
	}
	if e := authorize(arn); e != nil {
		return e
	}
	if e := ownedStore(r, scope, store); e != nil {
		return e
	}
	for _, resource := range []struct{ kind, id string }{{"user", user}, {"group", group}, {"membership", membership}} {
		if resource.id != "" {
			if e := authorize("arn:" + scope.Partition + ":identitystore:::" + resource.kind + "/" + resource.id); e != nil {
				return e
			}
		}
	}
	return nil
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) *awswire.Error      { return failure("ValidationException", message, 400) }
func conflict(message string) *awswire.Error { return failure("ConflictException", message, 400) }
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}
func wireError(e error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(e, &wire) {
		if wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException" {
			return failure("AccessDeniedException", wire.Message, 400)
		}
		return wire
	}
	if errors.Is(e, ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested identity store resource does not exist.", 400)
	}
	return &awswire.Error{Code: "InternalServerException", Message: "Unable to access Identity Store state.", StatusCode: 500, Cause: e}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func resourceID(store string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b[:])
	id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	if strings.HasPrefix(store, "d-") {
		id = store[2:] + "-" + id
	}
	return id, nil
}

// Only metadata is published until native field-level audit projections are calibrated.
// TODO: Comeback — calibrate Identity Store CloudTrail request/response projections.
func (s *Service) recordCall(ctx context.Context, action string, rejected *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	scope := scopeFor(ctx)
	call := journal.APICallCompleted{EventID: apievents.EventID(ctx), EventSource: "identitystore.amazonaws.com", EventName: action, Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "Get") || action == "IsMemberInGroups"}
	if rejected != nil {
		call.ErrorCode = rejected.Code
		call.ErrorMessage = rejected.Message
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), rejected)
}
