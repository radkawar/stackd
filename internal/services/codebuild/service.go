package codebuild

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	runtime "stackd/compute/codebuild"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type Config struct {
	Repository        Repository
	Authorizer        authorization.Authorizer
	Recorder          apievents.Recorder
	Clock             clock.Clock
	Executor          runtime.Executor
	Roles             BuildRoles
	Objects           Objects
	SourceBuckets     SourceBuckets
	PipelineArtifacts PipelineArtifacts
	Secrets           Secrets
	Parameters        Parameters
	Cipher            CredentialCipher
	Logs              BuildLogs
	Registry          Registry
	Events            EventPublisher
	ResourceShares    ResourceShares
	Endpoint          string
	FleetImage        string
}
type Service struct {
	repository        Repository
	authorizer        authorization.Authorizer
	recorder          apievents.Recorder
	clock             clock.Clock
	executor          runtime.Executor
	roles             BuildRoles
	objects           Objects
	sourceBuckets     SourceBuckets
	pipelineArtifacts PipelineArtifacts
	secrets           Secrets
	parameters        Parameters
	cipher            CredentialCipher
	logs              BuildLogs
	registry          Registry
	events            EventPublisher
	resourceShares    ResourceShares
	endpoint          string
	fleetImage        string
	jobs              *scheduler.Driver
	controller        *controller
	operations        map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, executor: c.Executor, roles: c.Roles, objects: c.Objects, secrets: c.Secrets, cipher: c.Cipher, logs: c.Logs, registry: c.Registry, events: c.Events, endpoint: c.Endpoint, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.parameters = c.Parameters
	s.sourceBuckets = c.SourceBuckets
	s.pipelineArtifacts = c.PipelineArtifacts
	s.fleetImage = c.FleetImage
	s.resourceShares = c.ResourceShares
	s.controller = newController(s)
	s.jobs = scheduler.New(c.Clock, deadlineJobs{s})
	register(s, "CreateProject", s.createProject)
	register(s, "UpdateProject", s.updateProject)
	register(s, "DeleteProject", s.deleteProject)
	register(s, "BatchGetProjects", s.batchGetProjects)
	register(s, "ListProjects", s.listProjects)
	s.operations["StartBuild"] = s.executeStartBuild
	register(s, "RetryBuild", s.retryBuild)
	register(s, "ListSharedProjects", s.listSharedProjects)
	s.operations["StopBuild"] = s.executeStopBuild
	register(s, "BatchGetBuilds", s.batchGetBuilds)
	register(s, "BatchDeleteBuilds", s.batchDeleteBuilds)
	register(s, "ListBuilds", s.listBuilds)
	register(s, "ListBuildsForProject", s.listBuildsForProject)
	register(s, "CreateFleet", s.createFleet)
	register(s, "UpdateFleet", s.updateFleet)
	register(s, "DeleteFleet", s.deleteFleet)
	register(s, "ListFleets", s.listFleets)
	register(s, "BatchGetFleets", s.batchGetFleets)
	register(s, "ImportSourceCredentials", s.importSourceCredentials)
	register(s, "DeleteSourceCredentials", s.deleteSourceCredentials)
	register(s, "ListSourceCredentials", s.listSourceCredentials)
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
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InvalidInputException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("codebuild")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// TODO: Comeback implement the remaining modeled CodeBuild batch, webhook,
// report, sandbox and source-provider connection workflows with real owners.
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	if fn := s.operations[string(request.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	rejected := unsupported("CodeBuild operation is not implemented: " + string(request.Operation.Name))
	if err := s.RecordRequestError(ctx, request, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InvalidInputException", "Missing request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx.Context(), tx, in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err != nil {
			rejected := wireError(err)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if e := s.recordCall(completion, action, in, nil, rejected); e != nil {
				return nil, wireError(e)
			}
			return nil, rejected
		}
		s.controller.wake()
		s.jobs.Wake()
		return out, nil
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown CodeBuild operation.")
	}
	return failure("InvalidInputException", err.Error())
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("codebuild")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	build, buildResult := out.(*BuildRecord)
	if buildResult {
		out = &api.StartBuildOutput{Build: &build.Data}
	}
	projection := auditProjection(action)
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	call.EventResources = auditProjectResources(scope, in)
	if err := completeAuditProjection(scope, action, &call); err != nil {
		return err
	}
	if buildResult {
		if err := completeBuildAudit(build, &call); err != nil {
			return err
		}
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func (s *Service) authorize(ctx context.Context, action, resource string, conditions map[string][]string) error {
	now := s.clock.Now()
	return errorOrNil(s.authorizer.Authorize(ctx, authorization.Request{Action: "codebuild:" + action, ResourceARN: resource, Context: conditions, EvaluationTime: &now}))
}
func errorOrNil(e *awswire.Error) error {
	if e == nil {
		return nil
	}
	return e
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
func unsupported(message string) *awswire.Error { return failure("InvalidInputException", message) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			return failure("AccessDeniedException", e.Message)
		}
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The specified CodeBuild resource does not exist.")
	}
	return &awswire.Error{Code: "InternalFailure", Message: "Unable to complete the CodeBuild operation.", StatusCode: 500}
}
