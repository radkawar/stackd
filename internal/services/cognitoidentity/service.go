package cognitoidentity

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/journal"
)

type TokenVerifier interface {
	VerifyIdentityToken(context.Context, string, string, string, bool) (map[string]any, error)
}
type CredentialRequest struct {
	PoolID, IdentityID, RoleARN string
	Authenticated               bool
	Expires                     time.Time
	Tags                        map[string]string
}
type CredentialIssuer interface {
	IssueIdentityCredentials(context.Context, CredentialRequest) (identity.Credential, error)
}
type Config struct {
	Repository  Repository
	Authorizer  authorization.Authorizer
	Recorder    apievents.Recorder
	Clock       clock.Clock
	Tokens      TokenVerifier
	Credentials CredentialIssuer
}
type Service struct {
	repository  Repository
	authorizer  authorization.Authorizer
	recorder    apievents.Recorder
	clock       clock.Clock
	tokens      TokenVerifier
	credentials CredentialIssuer
	operations  map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, tokens: c.Tokens, credentials: c.Credentials, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerPools(s)
	registerIdentities(s)
	registerRoles(s)
	registerPrincipalTags(s)
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
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalErrorException", "Missing generated binding."))
		return
	}
	out, denied := s.ExecuteCommand(r.Context(), req)
	if denied != nil {
		awswire.JSONError(w, r, denied)
		return
	}
	model, _ := awscatalog.LookupService("cognitoidentity")
	body, err := awsapi.EncodeResponse(model, req.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, req)
	action := string(req.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback — implement classic/developer token workflows through
		// authoritative token/IAM owners.
		return nil, &awswire.Error{Code: "NotImplementedException", Message: "Cognito Identity operation is not implemented: " + action, StatusCode: 501}
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalErrorException", "Missing generated binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		ctx = context.WithValue(ctx, auditKey{}, &auditScope{})
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.record(tx.Context(), action, in, out, nil)
		})
		if err == nil {
			return out, nil
		}
		denied := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e := s.record(completion, action, in, nil, denied); e != nil {
			return nil, wireError(e)
		}
		return nil, denied
	}
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown operation.")
	}
	var v *awsapi.ValidationError
	if errors.As(err, &v) && !v.TypeMismatch {
		return failure("InvalidParameterException", v.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func (s *Service) RecordRequestError(ctx context.Context, req awsapi.DecodedRequest, e *awswire.Error) error {
	return s.record(ctx, string(req.Operation.Name), req.Input, nil, e)
}

type auditKey struct{}
type auditScope struct{ scope Scope }

func notePool(ctx context.Context, k PoolKey) {
	if a, ok := ctx.Value(auditKey{}).(*auditScope); ok {
		a.scope = k.Scope
	}
}
func (s *Service) record(ctx context.Context, action string, in, out any, denied *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	scope := scopeFor(ctx)
	if a, ok := ctx.Value(auditKey{}).(*auditScope); ok && a.scope.AccountID != "" {
		scope = a.scope
	}
	if scope.AccountID == "" {
		return nil
	}
	model, _ := awscatalog.LookupService("cognitoidentity")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: slices.Contains([]string{"DescribeIdentityPool", "DescribeIdentity", "ListIdentityPools", "ListIdentities", "GetIdentityPoolRoles", "GetPrincipalTagAttributeMap", "ListTagsForResource"}, action), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"Logins": {Mode: awsapi.RedactValueField}}}}
	call, err := projection.Call(model, op, in, nil, denied)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	if awsctx.FromContext(ctx).PrincipalARN == "" {
		call.Identity = journal.APIIdentity{Type: "Unknown", PrincipalID: "Anonymous"}
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := 400
	if code == "InternalErrorException" {
		status = 500
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var w *awswire.Error
	if errors.As(err, &w) {
		return w
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Identity resource does not exist.")
	}
	return failure("InternalErrorException", "Unable to access identity state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
