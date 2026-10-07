package resourcegroups

import (
	"context"
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
	"stackd/internal/scheduler"
)

type Config struct {
	Repository           Repository
	Resources            Resources
	ApplicationResources ApplicationResources
	Roles                Roles
	Publisher            LifecyclePublisher
	Authorizer           authorization.Authorizer
	Recorder             apievents.Recorder
	Clock                clock.Clock
}

type Service struct {
	repository           Repository
	resources            Resources
	applicationResources ApplicationResources
	roles                Roles
	publisher            LifecyclePublisher
	authorizer           authorization.Authorizer
	recorder             apievents.Recorder
	clock                clock.Clock
	jobs                 *scheduler.Driver
	operations           map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, resources: c.Resources, applicationResources: c.ApplicationResources, roles: c.Roles, publisher: c.Publisher, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	register(s, "CreateGroup", s.createGroup)
	register(s, "DeleteGroup", s.deleteGroup)
	register(s, "GetGroup", s.getGroup)
	register(s, "UpdateGroup", s.updateGroup)
	register(s, "ListGroups", s.listGroups)
	register(s, "GetGroupQuery", s.getGroupQuery)
	register(s, "UpdateGroupQuery", s.updateGroupQuery)
	register(s, "SearchResources", s.searchResources)
	register(s, "ListGroupResources", s.listGroupResources)
	register(s, "GetTags", s.getTags)
	register(s, "Tag", s.tag)
	register(s, "Untag", s.untag)
	register(s, "GetGroupConfiguration", s.getGroupConfiguration)
	register(s, "PutGroupConfiguration", s.putGroupConfiguration)
	register(s, "GroupResources", s.groupResources)
	register(s, "UngroupResources", s.ungroupResources)
	register(s, "ListGroupingStatuses", s.listGroupingStatuses)
	register(s, "StartTagSyncTask", s.startTagSyncTask)
	register(s, "CancelTagSyncTask", s.cancelTagSyncTask)
	register(s, "GetTagSyncTask", s.getTagSyncTask)
	register(s, "ListTagSyncTasks", s.listTagSyncTasks)
	register(s, "GetAccountSettings", s.getAccountSettings)
	register(s, "UpdateAccountSettings", s.updateAccountSettings)
	s.jobs = scheduler.New(c.Clock, resourceGroupJobs{s})
	return s
}

func (s *Service) Operations() []string { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("resourcegroups")
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
	rejected := failure("UnknownOperationException", "Unknown Resource Groups operation.")
	if err := s.RecordRequestError(ctx, d, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated request binding.")
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
			if action == "StartTagSyncTask" || action == "CancelTagSyncTask" || action == "UpdateAccountSettings" {
				s.jobs.Wake()
			}
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) authorize(ctx context.Context, action string, g *Group, requestTags map[string]string, keys []string) error {
	arn := "*"
	conditions := map[string][]string{}
	if g != nil {
		arn = g.ARN
		for k, v := range g.Tags {
			conditions["aws:ResourceTag/"+k] = []string{v}
		}
	}
	for k, v := range requestTags {
		conditions["aws:RequestTag/"+k] = []string{v}
	}
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "resource-groups:" + action, ResourceARN: arn, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) loadGroup(r Reader, id, action string) (Group, error) {
	scope := scopeFor(r.Context())
	arn := id
	if !strings.HasPrefix(arn, "arn:") {
		arn = groupARN(scope, id)
	}
	g, ok, err := r.Group(scope, id)
	if err != nil {
		return Group{}, err
	}
	if !ok {
		g = Group{Scope: scope, ARN: arn}
	}
	if err := s.authorize(r.Context(), action, &g, nil, nil); err != nil {
		return Group{}, err
	}
	if !ok {
		return Group{}, failure("NotFoundException", "The specified group does not exist.")
	}
	if err := observeCloudFormationGroup(r.Context(), g); err != nil {
		return Group{}, err
	}
	return g, nil
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
func groupARN(s Scope, name string) string {
	return "arn:" + s.Partition + ":resource-groups:" + s.Region + ":" + s.AccountID + ":group/" + name
}
func identifier(group, name string) (string, error) {
	if group != "" && name != "" {
		return "", failure("BadRequestException", "Specify either Group or GroupName, not both.")
	}
	if group != "" {
		return group, nil
	}
	if name != "" {
		return name, nil
	}
	return "", failure("BadRequestException", "A group name or ARN is required.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	switch code {
	case "NotFoundException":
		status = http.StatusNotFound
	case "ForbiddenException", "AccessDeniedException", "AccessDenied":
		status = http.StatusForbidden
	case "UnauthorizedException":
		status = http.StatusUnauthorized
	case "MethodNotAllowedException":
		status = http.StatusMethodNotAllowed
	case "TooManyRequestsException":
		status = http.StatusTooManyRequests
	case "InternalServerErrorException":
		status = http.StatusInternalServerError
	case "NotImplementedException":
		status = http.StatusNotImplemented
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		return rejected
	}
	return failure("InternalServerErrorException", "Resource Groups request failed.")
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown Resource Groups operation.")
	}
	return failure("BadRequestException", err.Error())
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, rejected)
}
