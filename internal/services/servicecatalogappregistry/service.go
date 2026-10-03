package servicecatalogappregistry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/resourcegroups"
)

// Groups is the Resource Groups owner's application-specific transaction boundary.
type Groups interface {
	CreateApplicationGroups(context.Context, string, string, string, string) (string, string, error)
	UpdateApplicationGroups(context.Context, string, string) error
	DeleteApplicationGroups(context.Context, string) error
	AssociateApplicationStack(context.Context, string, string, resourcegroups.ApplicationResource) (string, error)
	DisassociateApplicationCollection(context.Context, string, string) error
	AssociateApplicationTagValue(context.Context, string, string, string, string) (string, error)
	ApplicationTagValueResources(context.Context, string) ([]resourcegroups.ApplicationResource, error)
	ApplyApplicationTags(context.Context, string, []resourcegroups.ApplicationResource, bool) error
}

type Config struct {
	Repository Repository
	Groups     Groups
	Resources  resourcegroups.ApplicationResources
	Roles      ApplicationRoles
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
}

type Service struct {
	repository Repository
	groups     Groups
	resources  resourcegroups.ApplicationResources
	roles      ApplicationRoles
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	operations map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, groups: c.Groups, resources: c.Resources, roles: c.Roles, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	register(s, "CreateApplication", s.createApplication)
	register(s, "GetApplication", s.getApplication)
	register(s, "UpdateApplication", s.updateApplication)
	register(s, "DeleteApplication", s.deleteApplication)
	register(s, "ListApplications", s.listApplications)
	register(s, "CreateAttributeGroup", s.createAttributeGroup)
	register(s, "GetAttributeGroup", s.getAttributeGroup)
	register(s, "UpdateAttributeGroup", s.updateAttributeGroup)
	register(s, "DeleteAttributeGroup", s.deleteAttributeGroup)
	register(s, "ListAttributeGroups", s.listAttributeGroups)
	register(s, "AssociateAttributeGroup", s.associateAttributeGroup)
	register(s, "DisassociateAttributeGroup", s.disassociateAttributeGroup)
	register(s, "ListAssociatedAttributeGroups", s.listAssociatedAttributeGroups)
	register(s, "ListAttributeGroupsForApplication", s.listAttributeGroupsForApplication)
	register(s, "AssociateResource", s.associateResource)
	register(s, "DisassociateResource", s.disassociateResource)
	register(s, "GetAssociatedResource", s.getAssociatedResource)
	register(s, "ListAssociatedResources", s.listAssociatedResources)
	// TODO: Comeback: SyncResource's legacy AppRegistry system-tag synchronization
	// requires a calibrated CloudFormation system-tag owner boundary. Do not map
	// it to awsApplication tagging or report unperformed synchronization success.
	register(s, "GetConfiguration", s.getConfiguration)
	register(s, "PutConfiguration", s.putConfiguration)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	return s
}
func (s *Service) Operations() []string { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("servicecatalogappregistry")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if fn, ok := s.operations[string(d.Operation.Name)]; ok {
		return fn(ctx)
	}
	rejected := failure("UnknownOperationException", "Unknown AppRegistry operation.")
	if err := s.RecordRequestError(ctx, d, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err == nil {
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		var denied interface{ RecordRejection(context.Context) error }
		if errors.As(err, &denied) {
			if err := denied.RecordRejection(completion); err != nil {
				return nil, wireError(err)
			}
		}
		if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags, requested map[string]string, keys []string) error {
	if arn == "" {
		arn = "*"
	}
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range requested {
		conditions["aws:RequestTag/"+k] = []string{v}
	}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	now := s.clock.Now()
	returnError := s.authorizer.Authorize(ctx, authorization.Request{Action: "servicecatalog:" + action, ResourceARN: arn, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now})
	if returnError != nil {
		return returnError
	}
	return nil
}
func (s *Service) loadApplication(r Reader, id, action string) (Application, error) {
	a, ok, err := r.Application(scopeFor(r.Context()), id)
	if err != nil {
		return a, err
	}
	arn := a.ARN
	if !ok {
		arn = applicationARN(scopeFor(r.Context()), id)
	}
	if err := s.authorize(r.Context(), action, arn, a.Tags, nil, nil); err != nil {
		return a, err
	}
	if !ok {
		return a, failure("ResourceNotFoundException", "Application not found.")
	}
	return a, nil
}
func (s *Service) loadAttributeGroup(r Reader, id, action string) (AttributeGroup, error) {
	a, ok, err := r.AttributeGroup(scopeFor(r.Context()), id)
	if err != nil {
		return a, err
	}
	arn := a.ARN
	if !ok {
		arn = attributeARN(scopeFor(r.Context()), id)
	}
	if err := s.authorize(r.Context(), action, arn, a.Tags, nil, nil); err != nil {
		return a, err
	}
	if !ok {
		return a, failure("ResourceNotFoundException", "Attribute group not found.")
	}
	return a, nil
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func resourceARN(s Scope, kind, id string) string {
	if strings.HasPrefix(id, "arn:") {
		return id
	}
	return "arn:" + s.Partition + ":servicecatalog:" + s.Region + ":" + s.AccountID + ":/" + kind + "/" + id
}
func applicationARN(s Scope, id string) string { return resourceARN(s, "applications", id) }
func attributeARN(s Scope, id string) string   { return resourceARN(s, "attribute-groups", id) }
func identifier() (string, error) {
	var b [13]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	switch code {
	case "ResourceNotFoundException":
		status = 404
	case "AccessDeniedException", "AccessDenied", "ForbiddenException":
		status = 403
	case "ConflictException":
		status = 409
	case "InternalServerException":
		status = 500
	case "NotImplementedException":
		status = 501
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		return e
	}
	return failure("InternalServerException", "AppRegistry request failed.")
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown AppRegistry operation.")
	}
	return failure("ValidationException", err.Error())
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
