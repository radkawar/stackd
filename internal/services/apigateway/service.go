package apigateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/apigatewayexec"
)

type LoggingConfiguration interface {
	apigatewayexec.LoggingConfiguration
	ConfigureLoggingRole(context.Context, string) error
}

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Endpoint     string
	Metrics      MetricPublisher
	Logs         LoggingConfiguration
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	endpoint   string
	operations map[string]func(context.Context) (any, *awswire.Error)
	usage      usageAdmission
	metrics    MetricPublisher
	logs       LoggingConfiguration
	jobs       *scheduler.Driver
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, endpoint: strings.TrimRight(c.Endpoint, "/"), operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.metrics = c.Metrics
	s.logs = c.Logs
	s.jobs = scheduler.New(c.Clock, metricJobs{s})
	register(s, "GetAccount", s.getAccount)
	register(s, "UpdateAccount", s.updateAccount)
	register(s, "CreateRestApi", s.createRestAPI)
	register(s, "GetRestApi", s.getRestAPI)
	register(s, "GetRestApis", s.getRestAPIs)
	register(s, "UpdateRestApi", s.updateRestAPI)
	register(s, "DeleteRestApi", s.deleteRestAPI)
	register(s, "CreateResource", s.createResource)
	register(s, "GetResource", s.getResource)
	register(s, "GetResources", s.getResources)
	register(s, "UpdateResource", s.updateResource)
	register(s, "DeleteResource", s.deleteResource)
	register(s, "PutMethod", s.putMethod)
	register(s, "GetMethod", s.getMethod)
	register(s, "UpdateMethod", s.updateMethod)
	register(s, "DeleteMethod", s.deleteMethod)
	register(s, "PutIntegration", s.putIntegration)
	register(s, "GetIntegration", s.getIntegration)
	register(s, "UpdateIntegration", s.updateIntegration)
	register(s, "DeleteIntegration", s.deleteIntegration)
	register(s, "CreateAuthorizer", s.createAuthorizer)
	register(s, "GetAuthorizer", s.getAuthorizer)
	register(s, "GetAuthorizers", s.getAuthorizers)
	register(s, "UpdateAuthorizer", s.updateAuthorizer)
	register(s, "DeleteAuthorizer", s.deleteAuthorizer)
	register(s, "CreateDeployment", s.createDeployment)
	register(s, "GetDeployment", s.getDeployment)
	register(s, "GetDeployments", s.getDeployments)
	register(s, "UpdateDeployment", s.updateDeployment)
	register(s, "DeleteDeployment", s.deleteDeployment)
	register(s, "CreateStage", s.createStage)
	register(s, "GetStage", s.getStage)
	register(s, "GetStages", s.getStages)
	register(s, "UpdateStage", s.updateStage)
	register(s, "DeleteStage", s.deleteStage)
	register(s, "FlushStageAuthorizersCache", s.flushStageAuthorizersCache)
	register(s, "CreateApiKey", s.createAPIKey)
	register(s, "GetApiKey", s.getAPIKey)
	register(s, "GetApiKeys", s.getAPIKeys)
	register(s, "UpdateApiKey", s.updateAPIKey)
	register(s, "DeleteApiKey", s.deleteAPIKey)
	register(s, "ImportApiKeys", s.importAPIKeys)
	register(s, "CreateUsagePlan", s.createUsagePlan)
	register(s, "GetUsagePlan", s.getUsagePlan)
	register(s, "GetUsagePlans", s.getUsagePlans)
	register(s, "UpdateUsagePlan", s.updateUsagePlan)
	register(s, "DeleteUsagePlan", s.deleteUsagePlan)
	register(s, "CreateUsagePlanKey", s.createUsagePlanKey)
	register(s, "GetUsagePlanKey", s.getUsagePlanKey)
	register(s, "GetUsagePlanKeys", s.getUsagePlanKeys)
	register(s, "DeleteUsagePlanKey", s.deleteUsagePlanKey)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "GetTags", s.getTags)
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
	model, _ := awscatalog.LookupService("apigateway")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalFailure", "Missing generated request binding.", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement the remaining REST control plane, including
		// custom domains, OpenAPI imports, models and nonproxy data-plane owners.
		e := failure("NotImplementedException", "API Gateway operation is not implemented: "+action, 501)
		if err := s.RecordRequestError(ctx, decoded, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated request binding.", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		var retained *awswire.Error
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(bindOwnership(tx), in)
			if err != nil {
				var partial *retainedFailure
				if errors.As(err, &partial) {
					retained = partial.cause
					return s.recordCall(tx.Context(), action, in, nil, retained)
				}
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err == nil {
			return out, retained
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
func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(decoded.Operation.Name), decoded.Input, nil, rejected)
}
func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	in, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("apigateway")
	if awsapi.BindHTTP(model, operation, request, in) != nil {
		return nil
	}
	return in
}
func (*Service) RequestError(operation string, err error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if operation == "CreateUsagePlan" && invalid.Path == "quota.period" && invalid.Constraint == "enum" {
			return failure("ValidationException", invalid.Error(), 400)
		}
		return bad(invalid.Error())
	}
	return bad("Invalid request body.")
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
func controlARN(scope Scope, path string) string {
	return "arn:" + scope.Partition + ":apigateway:" + scope.Region + "::" + path
}
func (s *Service) authorize(r Reader, verb, path string, tags map[string]string) error {
	scope := scopeFor(r.Context())
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	var requested api.MapOfStringToString
	if decoded, ok := awsapi.FromContext(r.Context()); ok {
		switch in := decoded.Input.(type) {
		case *api.CreateRestApiRequest:
			requested = in.Tags
			if in.EndpointConfiguration != nil && len(in.EndpointConfiguration.Types) > 0 {
				conditions["apigateway:Request/EndpointType"] = stringsIn(in.EndpointConfiguration.Types)
			}
		case *api.CreateStageRequest:
			requested = in.Tags
		case *api.CreateApiKeyRequest:
			requested = in.Tags
		case *api.CreateUsagePlanRequest:
			requested = in.Tags
		}
	}
	keys := make([]string, 0, len(requested))
	for k, v := range requested {
		keys = append(keys, string(k))
		conditions["aws:RequestTag/"+string(k)] = []string{string(v)}
	}
	if len(keys) > 0 {
		slices.Sort(keys)
		conditions["aws:TagKeys"] = keys
	}
	if e := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "apigateway:" + verb, ResourceARN: controlARN(scope, path), ResourceAccountID: scope.AccountID, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList", "apigateway:Request/EndpointType": "stringList"}}); e != nil {
		return e
	}
	return nil
}
func (s *Service) api(r Reader, id, verb, suffix string) (APIRecord, error) {
	row, err := r.API(APIKey{Scope: scopeFor(r.Context()), ID: id})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return row, err
	}
	tags, e := stageTags(r, row, suffix)
	if e != nil {
		return APIRecord{}, e
	}
	if e := s.authorize(r, verb, "/restapis/"+id+suffix, tags); e != nil {
		return APIRecord{}, e
	}
	return row, err
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) *awswire.Error { return failure("BadRequestException", message, 400) }
func unsupported(message string) *awswire.Error {
	return failure("BadRequestException", "Unsupported configuration: "+message, 400)
}
func conflict(message string) *awswire.Error { return failure("ConflictException", message, 409) }
func wireError(err error) *awswire.Error {
	if errors.Is(err, ErrNotFound) {
		return failure("NotFoundException", "Invalid resource identifier specified", 404)
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" || e.Code == "AccessDeniedException" {
			return failure("AccessDeniedException", e.Message, 403)
		}
		return e
	}
	slog.Error("API Gateway command failed", "error", err)
	return failure("InternalFailure", "Unable to complete API Gateway operation.", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func ptr(s string) *api.String { return new(api.String(s)) }
func optional(s string) *api.String {
	if s == "" {
		return nil
	}
	return ptr(s)
}
func truth[T ~bool](p *T) bool { return p != nil && bool(*p) }
func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func stringsIn[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
func stringsOut(in []string) api.ListOfString {
	out := make(api.ListOfString, len(in))
	for i, v := range in {
		out[i] = api.String(v)
	}
	return out
}
func mapIn(in api.MapOfStringToString) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}
func mapOut(in map[string]string) api.MapOfStringToString {
	if len(in) == 0 {
		return nil
	}
	out := make(api.MapOfStringToString, len(in))
	for k, v := range in {
		out[api.String(k)] = api.String(v)
	}
	return out
}
