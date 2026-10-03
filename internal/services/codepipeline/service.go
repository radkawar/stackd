package codepipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
	"time"
)

type Config struct {
	Repository Repository
	Executor   ActionExecutor
	Sources    SourceObserver
	Events     StateEvents
	Roles      Roles
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
}
type Service struct {
	repository Repository
	executor   ActionExecutor
	sources    SourceObserver
	events     StateEvents
	roles      Roles
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	jobs       *scheduler.Driver
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
	s := &Service{repository: c.Repository, executor: c.Executor, sources: c.Sources, events: c.Events, roles: c.Roles, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerDefinitions(s)
	registerExecutions(s)
	registerHistory(s)
	registerTags(s)
	registerInvocationJobs(s)
	s.jobs = scheduler.New(c.Clock, pipelineJobs{s})
	return s
}
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	name := string(d.Operation.Name)
	if f := s.operations[name]; f != nil {
		return f(ctx)
	}
	// TODO: Comeback — remaining modeled operations need their real provider,
	// webhook, worker, automatic stage-rule or resource-policy owners; all 44 stay targeted.
	e := failure("NotImplementedException", "CodePipeline operation is not implemented: "+name)
	if err := s.authorize(ctx, name, "*", nil); err != nil {
		e = wireError(err)
	}
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalFailure", "Missing generated request binding"))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	model, _ := awscatalog.LookupService("codepipeline")
	response, err := awsapi.EncodeHTTPResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func register[I, O any](s *Service, name string, fn func(Transaction, *I) (*O, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated input")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), name, in, out, nil)
		})
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordCall(completion, name, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags map[string]string) error {
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	if d, ok := awsapi.FromContext(ctx); ok {
		addRequestTags(conditions, d.Input)
	}
	now := s.clock.Now()
	if err := s.authorizer.Authorize(ctx, authorization.Request{Action: "codepipeline:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); err != nil {
		return err
	}
	return nil
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("codepipeline")
	op, ok := model.Operation(name)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List")}
	if name == "CreatePipeline" || name == "UpdatePipeline" || name == "StartPipelineExecution" || name == "StopPipelineExecution" || name == "RetryStageExecution" || name == "RollbackStage" || name == "PutApprovalResult" {
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	call.EventSource = "codepipeline.amazonaws.com"
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, At: s.clock.Now()}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	return failure("ValidationException", err.Error())
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func scopedContext(ctx context.Context, sc Scope) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = sc.Partition, sc.AccountID, sc.Region
	return awsctx.WithMetadata(ctx, m)
}
func ARN(sc Scope, name string) string {
	return "arn:" + sc.Partition + ":codepipeline:" + sc.Region + ":" + sc.AccountID + ":" + name
}
func failure(code, message string) *awswire.Error {
	status := 400
	if code == "InternalFailure" {
		status = 500
	}
	if code == "NotImplementedException" {
		status = 501
	}
	if code == "AccessDeniedException" {
		status = 403
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			denied := *e
			denied.Code = "AccessDeniedException"
			return &denied
		}
		return e
	}
	return failure("InternalFailure", err.Error())
}
func value[T any](v *T) (zero T) {
	if v != nil {
		return *v
	}
	return
}
func text[T ~string](v *T) string { return string(value(v)) }
func newID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:], nil
}
func findPipeline(r Reader, sc Scope, name string) (Pipeline, error) {
	rows, err := r.Pipelines(sc)
	if err != nil {
		return Pipeline{}, err
	}
	for _, v := range rows {
		if v.Name == name {
			return v, nil
		}
	}
	return Pipeline{}, failure("PipelineNotFoundException", "Pipeline not found: "+name)
}
func findDefinition(r Reader, p Pipeline, version int32) (Definition, error) {
	d, ok, err := r.Definition(p.Scope, p.Incarnation, version)
	if err != nil {
		return d, err
	}
	if !ok {
		return d, failure("PipelineVersionNotFoundException", "Pipeline version not found")
	}
	return d, nil
}
func findExecution(r Reader, p Pipeline, id string) (Execution, error) {
	rows, err := r.Executions(p.Scope, p.Incarnation)
	if err != nil {
		return Execution{}, err
	}
	for _, e := range rows {
		if e.ID == id {
			return e, nil
		}
	}
	return Execution{}, failure("PipelineExecutionNotFoundException", "Pipeline execution not found: "+id)
}
func (s *Service) saveExecution(tx Transaction, p Pipeline, e Execution) error {
	if err := tx.PutExecution(e); err != nil {
		return err
	}
	if s.events != nil {
		return s.events.PipelineStateChanged(tx.Context(), p, e)
	}
	return nil
}
func (s *Service) actionEvent(tx Transaction, p Pipeline, e Execution, a ActionExecution, decl api.ActionDeclaration) error {
	if s.events != nil {
		return s.events.ActionStateChanged(tx.Context(), p, e, a, decl)
	}
	return nil
}
func (s *Service) stageEvent(tx Transaction, p Pipeline, e *Execution, stage, state string) error {
	if !e.StageEntered || e.StageStatus == state {
		return nil
	}
	e.StageStatus = state
	if s.events != nil {
		return s.events.StageStateChanged(tx.Context(), p, *e, stage, state)
	}
	return nil
}
func terminal(status string) bool { return status != "InProgress" && status != "Stopping" }
func finish(e *Execution, status, summary string, now time.Time) {
	e.Status = status
	e.Summary = summary
	e.UpdatedAt = now
	e.Due = time.Time{}
	e.Generation++
}
