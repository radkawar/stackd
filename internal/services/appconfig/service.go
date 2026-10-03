package appconfig

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
	"stackd/internal/scheduler"
	"stackd/journal"
)

type Config struct {
	Repository        Repository
	Effects           Effects
	StrategyDocuments StrategyDocuments
	Authorizer        authorization.Authorizer
	Recorder          apievents.Recorder
	Clock             clock.Clock
}
type Service struct {
	repository                 Repository
	effects                    Effects
	strategyDocuments          StrategyDocuments
	authorizer                 authorization.Authorizer
	recorder                   apievents.Recorder
	clock                      clock.Clock
	jobs                       *scheduler.Driver
	operations, dataOperations map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, effects: c.Effects, strategyDocuments: c.StrategyDocuments, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, operations: map[string]func(context.Context) (any, *awswire.Error){}, dataOperations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerControls(s)
	registerDeployments(s)
	registerDataOperations(s)
	registerExtensions(s)
	registerSettings(s)
	registerTags(s)
	registerExperiments(s)
	s.jobs = scheduler.New(c.Clock, appconfigJobs{s})
	return s
}
func (s *Service) Operations() []string         { return slices.Sorted(maps.Keys(s.operations)) }
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) wake(context.Context) {
	if s.jobs != nil {
		s.jobs.Wake()
	}
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	action := string(d.Operation.Name)
	if fn := s.operations[action]; fn != nil {
		return fn(ctx)
	}
	if fn := s.dataOperations[action]; fn != nil {
		return fn(ctx)
	}
	rejected := failure("NotImplementedException", "AppConfig operation is not implemented: "+action)
	if err := s.authorize(ctx, action, "*", nil); err != nil {
		rejected = wireError(err)
	}
	if err := s.RecordRequestError(ctx, d, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.serveHTTP("appconfig", w, r) }
func (s *Service) serveHTTP(service string, w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService(service)
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerException", "Missing generated request binding."))
		return
	}
	var request configurationRequest
	ctx := r.Context()
	if service == "appconfigdata" {
		request.accept = r.Header.Get("Accept")
		ctx = context.WithValue(ctx, configurationRequestKey{}, &request)
	}
	out, rejected := s.ExecuteCommand(ctx, d)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, d.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	for k, v := range request.headers {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

type dataFrontend struct{ *Service }

func (s *Service) DataHandler() *dataFrontend { return &dataFrontend{s} }
func (d *dataFrontend) Operations() []string  { return slices.Sorted(maps.Keys(d.dataOperations)) }
func (d *dataFrontend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.serveHTTP("appconfigdata", w, r)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	registerExternal(s, action, func(ctx context.Context, in *I) (out *O, err error) {
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		return
	})
}
func registerData[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	registerExternalData(s, action, func(ctx context.Context, in *I) (out *O, err error) {
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		return
	})
}
func registerExternal[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.operations[action] = command(s, action, fn)
}
func registerExternalData[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) {
	s.dataOperations[action] = command(s, action, fn)
}
func command[I, O any](s *Service, action string, fn func(context.Context, *I) (*O, error)) func(context.Context) (any, *awswire.Error) {
	return func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerException", "Missing generated input.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		if action == "StartConfigurationSession" || action == "GetLatestConfiguration" {
			ctx = context.WithValue(ctx, dataResourceKey{}, &dataResource{})
		}
		out, err := fn(ctx, in)
		if err == nil {
			s.wake(ctx)
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
func (s *Service) authorize(ctx context.Context, action, resource string, tags map[string]string) error {
	values := requestTagContext(ctx)
	for k, v := range tags {
		values["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "appconfig:" + action, ResourceARN: resource, Context: values, EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}
func (s *Service) passRole(ctx context.Context, role string) error {
	if role == "" {
		return nil
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: role, Context: map[string][]string{"iam:PassedToService": {"appconfig.amazonaws.com"}}, EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	name := "appconfig"
	category := journal.CategoryManagement
	if action == "StartConfigurationSession" || action == "GetLatestConfiguration" {
		name = "appconfigdata"
		category = journal.CategoryData
	}
	model, _ := awscatalog.LookupService(name)
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: category, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List"), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"Content": {Mode: awsapi.RedactValueField}, "ConfigurationToken": {Mode: awsapi.OmitField}, "Validators.Content": {Mode: awsapi.RedactValueField}}}}
	switch action {
	case "CreateApplication", "CreateConfigurationProfile", "CreateHostedConfigurationVersion", "StartDeployment":
		projection.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"Content": {Mode: awsapi.RedactValueField}, "Validators.Content": {Mode: awsapi.RedactValueField}}}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	call.EventSource = "appconfig.amazonaws.com"
	if category == journal.CategoryData {
		resources, err := s.dataEventResources(ctx, in, out)
		if err != nil {
			return err
		}
		call.EventResources = resources
	}
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, At: s.clock.Now()}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	return failure("BadRequestException", err.Error())
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
func failure(code, message string) *awswire.Error {
	status := 400
	switch code {
	case "InternalServerException":
		status = 500
	case "ResourceNotFoundException":
		status = 404
	case "AccessDeniedException", "AccessDenied":
		status = 403
	case "ConflictException":
		status = 409
	case "ServiceQuotaExceededException":
		status = 402
	case "PayloadTooLargeException":
		status = 413
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
	return &awswire.Error{Code: "InternalServerException", Message: "Unable to access AppConfig state.", StatusCode: 500, Cause: err}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func number[T ~int32](p *T) int32 {
	if p == nil {
		return 0
	}
	return int32(*p)
}
func boolean[T ~bool](p *T) bool { return p != nil && bool(*p) }
func newID() string              { var b [4]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:])[:7] }
