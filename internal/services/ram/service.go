package ram

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/identitystore"
	"stackd/journal"
)

type ResourceSharingAuthorizer interface {
	AuthorizeResourceSharing(context.Context, string) error
}
type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Resources    ResourceOwner
	Organization Organization
	// ResourceTypes lists only the kinds backed by the configured owner.
	ResourceTypes []string
}
type Service struct {
	repository    Repository
	authorizer    authorization.Authorizer
	binder        authorization.PolicyBinder
	recorder      apievents.Recorder
	clock         clock.Clock
	resources     ResourceOwner
	organization  Organization
	resourceTypes []string
	managed       []Permission
	tokenKey      [32]byte
	operations    map[string]func(context.Context) (any, *awswire.Error)
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
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, resources: c.Resources, organization: c.Organization, resourceTypes: slices.Clone(c.ResourceTypes), managed: managedPermissions(), operations: map[string]func(context.Context) (any, *awswire.Error){}}
	slices.Sort(s.resourceTypes)
	_, _ = rand.Read(s.tokenKey[:])
	register(s, "CreateResourceShare", s.createResourceShare)
	register(s, "UpdateResourceShare", s.updateResourceShare)
	register(s, "DeleteResourceShare", s.deleteResourceShare)
	register(s, "AssociateResourceShare", s.associateResourceShare)
	register(s, "DisassociateResourceShare", s.disassociateResourceShare)
	register(s, "GetResourceShares", s.getResourceShares)
	register(s, "GetResourceShareAssociations", s.getResourceShareAssociations)
	register(s, "GetResourceShareInvitations", s.getResourceShareInvitations)
	register(s, "AcceptResourceShareInvitation", s.acceptResourceShareInvitation)
	register(s, "RejectResourceShareInvitation", s.rejectResourceShareInvitation)
	register(s, "ListPendingInvitationResources", s.listPendingInvitationResources)
	register(s, "ListResources", s.listResources)
	register(s, "ListPrincipals", s.listPrincipals)
	register(s, "ListResourceTypes", s.listResourceTypes)
	register(s, "GetResourcePolicies", s.getResourcePolicies)
	register(s, "EnableSharingWithAwsOrganization", s.enableSharingWithAwsOrganization)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "GetPermission", s.getPermission)
	register(s, "ListPermissions", s.listPermissions)
	register(s, "ListPermissionVersions", s.listPermissionVersions)
	register(s, "ListResourceSharePermissions", s.listResourceSharePermissions)
	register(s, "CreatePermission", s.createPermission)
	register(s, "CreatePermissionVersion", s.createPermissionVersion)
	register(s, "SetDefaultPermissionVersion", s.setDefaultPermissionVersion)
	register(s, "DeletePermission", s.deletePermission)
	register(s, "DeletePermissionVersion", s.deletePermissionVersion)
	register(s, "AssociateResourceSharePermission", s.associateResourceSharePermission)
	register(s, "DisassociateResourceSharePermission", s.disassociateResourceSharePermission)
	register(s, "ListPermissionAssociations", s.listPermissionAssociations)
	register(s, "ReplacePermissionAssociations", s.replacePermissionAssociations)
	register(s, "ListReplacePermissionAssociationsWork", s.listReplacePermissionAssociationsWork)
	register(s, "PromotePermissionCreatedFromPolicy", s.promotePermissionCreatedFromPolicy)
	register(s, "PromoteResourceShareCreatedFromPolicy", s.promoteResourceShareCreatedFromPolicy)
	register(s, "ListSourceAssociations", s.listSourceAssociations)
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
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("ram")
	req, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("ServerInternalException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), req)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	body, e := awsapi.EncodeResponse(model, req.Operation, out)
	if e != nil {
		awswire.JSONError(w, r, wireError(e))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, r)
	fn, ok := s.operations[string(r.Operation.Name)]
	if !ok {
		e := failure("UnknownOperationException", "RAM operation is not recognized.")
		if err := s.RecordRequestError(ctx, r, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
	return fn(ctx)
}
func register[I, O any](s *Service, op string, fn func(Transaction, *I) (*O, error)) {
	s.operations[op] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("ServerInternalException", "Missing generated request binding.")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx, in)
			if err != nil {
				return err
			}
			if err = s.authorizeCreationTags(tx, in, out); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), op, in, out, nil)
		})
		if e == nil {
			return out, nil
		}
		rejected := wireError(e)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e = s.recordCall(completion, op, in, nil, rejected); e != nil {
			return nil, wireError(e)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (s *Service) RequestError(_ string, e error) *awswire.Error {
	if errors.Is(e, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown RAM operation.")
	}
	var v *awsapi.ValidationError
	if errors.As(e, &v) {
		return failure("InvalidParameterException", v.Error())
	}
	return failure("InvalidParameterException", "Invalid request body.")
}
func (s *Service) recordCall(ctx context.Context, op string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ram")
	operation, ok := model.Operation(op)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(op, "Get") || strings.HasPrefix(op, "List"), Response: &awsapi.DocumentProjection{}}
	call, e := projection.Call(model, operation, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := 400
	if code == "ServerInternalException" {
		status = 500
	}
	if code == "AccessDeniedException" {
		status = 403
	}
	if code == "PermissionAlreadyExistsException" {
		status = 409
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(e error) *awswire.Error {
	if e == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(e, &w) {
		if w.Code == "AccessDenied" {
			return failure("AccessDeniedException", w.Message)
		}
		return w
	}
	if errors.Is(e, ErrNotFound) {
		return failure("UnknownResourceException", "The specified resource was not found.")
	}
	if errors.Is(e, ErrUnsupportedResource) {
		return failure("InvalidResourceTypeException", "No supported resource owner exists for this resource type.")
	}
	return failure("ServerInternalException", "Unable to access RAM state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
func arnFor(sc Scope, kind, id string) string {
	return "arn:" + sc.Partition + ":ram:" + sc.Region + ":" + sc.AccountID + ":" + kind + "/" + id
}
func receipt(tx Transaction, op string, token *api.String, in any) (Receipt, bool, error) {
	if token == nil {
		return Receipt{}, false, nil
	}
	if len(*token) == 0 || len(*token) > 64 {
		return Receipt{}, false, failure("InvalidClientTokenException", "Client token must contain 1 to 64 characters.")
	}
	data, e := receiptParameters(in)
	if e != nil {
		return Receipt{}, false, e
	}
	hash := sha256.Sum256(data)
	r := Receipt{Scope: scopeFor(tx.Context()), Operation: op, Token: string(*token), Hash: hex.EncodeToString(hash[:]), CloudFormationOwner: identitystore.CloudFormationOwner(tx.Context())}
	old, e := tx.Receipt(r.Scope, op, r.Token)
	if e == nil {
		if r.CloudFormationOwner != "" && r.CloudFormationOwner != old.CloudFormationOwner {
			return r, false, notOwned("Operation receipt")
		}
		if old.Hash != r.Hash {
			if op == "AssociateResourceSharePermission" || op == "DisassociateResourceSharePermission" {
				return r, false, failure("InvalidClientTokenException", r.Token)
			}
			return r, false, failure("IdempotentParameterMismatchException", "The client token was used with different parameters.")
		}
		return old, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return r, false, e
	}
	return r, false, nil
}

func saveReceipt(tx Transaction, r Receipt) error {
	if r.Token == "" {
		return nil
	}
	return tx.PutReceipt(r)
}

// receiptParameters excludes the lookup token without modifying the caller's request.
func receiptParameters(in any) ([]byte, error) {
	switch v := in.(type) {
	case *api.CreateResourceShareRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.UpdateResourceShareRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.DeleteResourceShareRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.AssociateResourceShareRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.DisassociateResourceShareRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.AcceptResourceShareInvitationRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.RejectResourceShareInvitationRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.CreatePermissionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.CreatePermissionVersionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.SetDefaultPermissionVersionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.DeletePermissionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.DeletePermissionVersionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.AssociateResourceSharePermissionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.DisassociateResourceSharePermissionRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.ReplacePermissionAssociationsRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	case *api.PromotePermissionCreatedFromPolicyRequest:
		p := *v
		p.ClientToken = nil
		return json.Marshal(p)
	default:
		return nil, failure("ServerInternalException", "Missing RAM receipt parameter binding.")
	}
}
