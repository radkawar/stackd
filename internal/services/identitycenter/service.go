package identitycenter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"stackd/internal/services/identitystore"
	"stackd/journal"
	"strings"
)

type Config struct {
	Repository     Repository
	Directory      Directory
	Login          Login
	Roles          Roles
	Accounts       Accounts
	Authorizer     authorization.Authorizer
	Recorder       apievents.Recorder
	Clock          clock.Clock
	PublicEndpoint string
}
type Service struct {
	repository Repository
	directory  Directory
	login      Login
	roles      Roles
	accounts   Accounts
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	endpoint   string
	operations map[string]map[string]func(context.Context) (any, *awswire.Error)
}

func New(c Config) *Service {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, directory: c.Directory, login: c.Login, roles: c.Roles, accounts: c.Accounts, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, endpoint: strings.TrimRight(c.PublicEndpoint, "/"), operations: map[string]map[string]func(context.Context) (any, *awswire.Error){"ssoadmin": {}, "ssooidc": {}, "sso": {}}}
	s.registerAdministration()
	s.registerPermissions()
	s.registerAssignments()
	s.registerOIDC()
	s.registerPortal()
	return s
}

type Frontend struct {
	s    *Service
	name string
}

func (s *Service) Frontend(name string) *Frontend { return &Frontend{s, name} }
func (f *Frontend) Operations() []string {
	out := make([]string, 0, len(f.s.operations[f.name]))
	for name := range f.s.operations[f.name] {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func (f *Frontend) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	fn, ok := f.s.operations[f.name][string(d.Operation.Name)]
	if !ok {
		// TODO: Comeback — Identity Center applications, CreateTokenWithIAM, trusted-token issuers and access-control attributes require their actual consumer flows.
		return nil, failure("NotImplementedException", "Identity Center operation is not implemented: "+string(d.Operation.Name), 501)
	}
	return fn(ctx)
}
func (f *Frontend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, bad("Missing generated request binding."))
		return
	}
	out, rejected := f.ExecuteCommand(r.Context(), d)
	model, _ := awscatalog.LookupService(f.name)
	if rejected != nil {
		if f.name == "ssoadmin" {
			awswire.JSONError(w, r, rejected)
		} else {
			awswire.RESTJSONError(w, r, &model, rejected)
		}
		return
	}
	body, e := awsapi.EncodeResponse(model, d.Operation, out)
	if e != nil {
		awswire.JSONError(w, r, wireError(e))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (f *Frontend) RequestError(_ string, e error) *awswire.Error {
	if f.name == "ssooidc" {
		return oauthError("InvalidRequestException", "invalid_request", "Invalid request.", 400)
	}
	return bad(e.Error())
}
func (f *Frontend) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return f.s.record(ctx, f.name, string(d.Operation.Name), d.Input, nil, e)
}

// committedRejection retains protocol state transitions such as device polling
// admission while returning an OAuth rejection; ordinary errors still roll back.
type committedRejection struct{ wire *awswire.Error }

func (e *committedRejection) Error() string { return e.wire.Error() }
func register[I, O any](s *Service, service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[service][action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, bad("Missing generated request binding.")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		var rejection *awswire.Error
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx, in)
			var committed *committedRejection
			if errors.As(err, &committed) {
				rejection = committed.wire
				return s.record(tx.Context(), service, action, in, nil, rejection)
			}
			if err != nil {
				return err
			}
			return s.record(tx.Context(), service, action, in, out, nil)
		})
		if e != nil {
			rejection = wireError(e)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if e = s.record(completion, service, action, in, nil, rejection); e != nil {
				return nil, wireError(e)
			}
		}
		if rejection != nil {
			return nil, rejection
		}
		return out, nil
	}
}
func (s *Service) record(ctx context.Context, service, action string, in, out any, rejected *awswire.Error) error {
	// Browser credentials and OIDC bearer material never enter diagnostic events.
	// TODO: Comeback — native OIDC/portal audit event selection and identity projection are not calibrated.
	if s.recorder == nil || service != "ssoadmin" {
		return nil
	}
	model, _ := awscatalog.LookupService(service)
	op, _ := model.Operation(action)
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Describe")}
	call, e := p.Call(model, op, in, out, rejected)
	if e != nil {
		return e
	}
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func directoryScope(i Instance) identitystore.Scope {
	return identitystore.Scope{Partition: i.Partition, AccountID: i.AccountID, Region: i.Region}
}
func (s *Service) authorize(ctx context.Context, action, arn string) error {
	return s.authorizeTags(ctx, action, arn, nil, nil)
}
func (s *Service) authorizeTags(ctx context.Context, action, arn string, tags, requestTags map[string]string) error {
	now := s.clock.Now()
	conditions := map[string][]string{"sso:PrimaryRegion": {scopeFor(ctx).Region}}
	for key, v := range tags {
		conditions["aws:ResourceTag/"+key] = []string{v}
	}
	for key, v := range requestTags {
		conditions["aws:RequestTag/"+key] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: "sso:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}
func (s *Service) instance(r Reader, arn, action string) (Instance, error) {
	v, e := r.Instance(arn)
	if e != nil {
		return v, e
	}
	if v.Scope != scopeFor(r.Context()) {
		return Instance{}, ErrNotFound
	}
	if e = s.authorizeTags(r.Context(), action, arn, v.Tags, nil); e != nil {
		return Instance{}, e
	}
	return v, nil
}
func (s *Service) permission(r Reader, instance, arn, action string) (Instance, PermissionSet, error) {
	i, e := s.instance(r, instance, action)
	if e != nil {
		return i, PermissionSet{}, e
	}
	p, e := r.PermissionSet(arn)
	if e != nil {
		return i, p, e
	}
	if p.InstanceARN != i.ARN {
		return i, PermissionSet{}, ErrNotFound
	}
	if e = s.authorizeTags(r.Context(), action, p.ARN, p.Tags, nil); e != nil {
		return i, p, e
	}
	return i, p, nil
}

// Instances and permission sets carry a private CloudFormation incarnation
// claim. Public tags never establish ownership. Controller observers see a
// foreign row as absent; controller mutations are denied in the same
// transaction as their IAM authorization. Requests without trusted controller
// provenance remain ordinary IAM requests.
func claimCheck(ctx context.Context, stored, action string) error {
	owner := identitystore.CloudFormationOwner(ctx)
	if owner == "" || owner == stored {
		return nil
	}
	if strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") {
		return ErrNotFound
	}
	return failure("AccessDeniedException", "The resource is not owned by this CloudFormation incarnation.", 400)
}
func (s *Service) ownedInstance(r Reader, arn, action string) (Instance, error) {
	v, e := s.instance(r, arn, action)
	if e != nil {
		return v, e
	}
	if e = claimCheck(r.Context(), v.CloudFormationOwner, action); e != nil {
		return Instance{}, e
	}
	return v, nil
}

// ownedPermission serves permission-set operations. Assignment operations use
// permission directly because assignments carry their own incarnation claim.
func (s *Service) ownedPermission(r Reader, instance, arn, action string) (Instance, PermissionSet, error) {
	i, p, e := s.permission(r, instance, arn, action)
	if e != nil {
		return i, p, e
	}
	if e = claimCheck(r.Context(), p.CloudFormationOwner, action); e != nil {
		return i, PermissionSet{}, e
	}
	return i, p, nil
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) *awswire.Error { return failure("ValidationException", message, 400) }
func wireError(e error) *awswire.Error {
	var w *awswire.Error
	if errors.As(e, &w) {
		if w.Code == "AccessDenied" {
			return failure("AccessDeniedException", w.Message, 400)
		}
		return w
	}
	if errors.Is(e, ErrNotFound) || errors.Is(e, identitystore.ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested resource does not exist.", 400)
	}
	return &awswire.Error{Code: "InternalServerException", Message: "Unable to access Identity Center state.", StatusCode: 500, Cause: e}
}
func oauthError(code, oauth, message string, status int) *awswire.Error {
	a, _ := json.Marshal(oauth)
	b, _ := json.Marshal(message)
	return &awswire.Error{Code: code, Message: message, StatusCode: status, Details: map[string]json.RawMessage{"error": a, "error_description": b}}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func randomToken() (string, error) {
	var v [32]byte
	if _, e := rand.Read(v[:]); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(v[:]), nil
}
func randomHex(bytes int) (string, error) {
	v := make([]byte, bytes)
	if _, e := rand.Read(v); e != nil {
		return "", e
	}
	return hex.EncodeToString(v), nil
}
func tokenHash(raw string) string { v := sha256.Sum256([]byte(raw)); return hex.EncodeToString(v[:]) }
