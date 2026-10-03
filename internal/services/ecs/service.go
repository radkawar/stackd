package ecs

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	runtime "stackd/compute/ecs"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"strings"
)

type Config struct {
	Repository       Repository
	Authorizer       authorization.Authorizer
	Recorder         apievents.Recorder
	Clock            clock.Clock
	Roles            ServiceRoles
	Executor         runtime.Executor
	TaskRoles        TaskRoles
	Networks         TaskNetworks
	Logs             TaskLogs
	Parameters       TaskParameters
	EnvironmentFiles TaskEnvironmentFiles
	Events           TaskEventPublisher
	Metrics          MetricPublisher
	ServiceState     ServiceStateObserver
	LoadBalancers    ServiceLoadBalancers
	Endpoint         string
}
type Service struct {
	repository       Repository
	authorizer       authorization.Authorizer
	recorder         apievents.Recorder
	clock            clock.Clock
	roles            ServiceRoles
	executor         runtime.Executor
	taskRoles        TaskRoles
	networks         TaskNetworks
	logs             TaskLogs
	parameters       TaskParameters
	environmentFiles TaskEnvironmentFiles
	events           TaskEventPublisher
	metrics          MetricPublisher
	serviceState     ServiceStateObserver
	loadBalancers    ServiceLoadBalancers
	jobs             *scheduler.Driver
	endpoint         string
	tasks            *taskController
	operations       map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, roles: c.Roles, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.executor, s.taskRoles, s.networks, s.logs, s.events, s.endpoint = c.Executor, c.TaskRoles, c.Networks, c.Logs, c.Events, c.Endpoint
	s.parameters = c.Parameters
	s.environmentFiles = c.EnvironmentFiles
	s.tasks = newTaskController(s)
	s.metrics = c.Metrics
	s.serviceState = c.ServiceState
	s.loadBalancers = c.LoadBalancers
	s.jobs = scheduler.New(c.Clock, metricJobs{s})
	register(s, "CreateCluster", s.createCluster)
	register(s, "DescribeClusters", s.describeClusters)
	register(s, "ListClusters", s.listClusters)
	register(s, "UpdateCluster", s.updateCluster)
	register(s, "UpdateClusterSettings", s.updateClusterSettings)
	register(s, "DeleteCluster", s.deleteCluster)
	register(s, "RegisterTaskDefinition", s.registerTaskDefinition)
	register(s, "DescribeTaskDefinition", s.describeTaskDefinition)
	register(s, "ListTaskDefinitions", s.listTaskDefinitions)
	register(s, "ListTaskDefinitionFamilies", s.listTaskDefinitionFamilies)
	register(s, "DeregisterTaskDefinition", s.deregisterTaskDefinition)
	register(s, "DeleteTaskDefinitions", s.deleteTaskDefinitions)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "RunTask", s.runTask, s.tasks.wake)
	register(s, "DescribeTasks", s.describeTasks)
	register(s, "ListTasks", s.listTasks)
	register(s, "StopTask", s.stopTask, s.tasks.wake)
	register(s, "CreateService", s.createService, s.tasks.wake)
	register(s, "DescribeServices", s.describeServices)
	register(s, "DescribeServiceRevisions", s.describeServiceRevisions)
	register(s, "ListServices", s.listServices)
	register(s, "UpdateService", s.updateService, s.tasks.wake)
	register(s, "DeleteService", s.deleteService, s.tasks.wake)
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
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("ServerException", "Missing generated ECS request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ecs")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement the remaining ECS execution and service
		// lifecycle operations; generated recognition is not behavior.
		rejected := unsupported("ECS operation requires an unimplemented execution or external service dependency: " + action)
		if err := s.RecordRequestError(ctx, decoded, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error), committed ...func()) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("ServerException", "Missing generated ECS request binding.", 500)
		}
		return runCommand(s, ctx, action, in, fn, committed...)
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (*Service) RequestError(action string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested ECS operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		code := "InvalidParameterException"
		if invalid.Constraint == "enum" && (action == "RegisterTaskDefinition" || action == "DescribeTaskDefinition") {
			code = "ClientException"
		}
		return failure(code, invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func failure(code, message string, status ...int) *awswire.Error {
	n := 400
	if len(status) > 0 {
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
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ClientException", "The specified resource does not exist.")
	}
	return failure("ServerException", "Unable to access ECS state.", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags api.Tags, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for _, tag := range tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
		conditions["ecs:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	if (action == "TagResource" || action == "UntagResource") && strings.Contains(arn, ":cluster/") {
		conditions["ecs:cluster"] = []string{arn}
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "ecs:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
