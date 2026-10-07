package apigatewayv2

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayexec"
)

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Endpoint     string
	Logs         apigatewayexec.LoggingConfiguration
	Certificates DomainCertificates
	Truststores  DomainTruststores
}
type Service struct {
	repository   Repository
	authorizer   authorization.Authorizer
	recorder     apievents.Recorder
	clock        clock.Clock
	endpoint     string
	logs         apigatewayexec.LoggingConfiguration
	certificates DomainCertificates
	truststores  DomainTruststores
	operations   map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, endpoint: strings.TrimRight(c.Endpoint, "/"), logs: c.Logs, certificates: c.Certificates, truststores: c.Truststores, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	register(s, "CreateApi", s.createAPI)
	register(s, "GetApi", s.getAPI)
	register(s, "GetApis", s.getAPIs)
	register(s, "UpdateApi", s.updateAPI)
	register(s, "DeleteApi", s.deleteAPI)
	register(s, "CreateIntegration", s.createIntegration)
	register(s, "GetIntegration", s.getIntegration)
	register(s, "GetIntegrations", s.getIntegrations)
	register(s, "UpdateIntegration", s.updateIntegration)
	register(s, "DeleteIntegration", s.deleteIntegration)
	register(s, "CreateAuthorizer", s.createAuthorizer)
	register(s, "GetAuthorizer", s.getAuthorizer)
	register(s, "GetAuthorizers", s.getAuthorizers)
	register(s, "UpdateAuthorizer", s.updateAuthorizer)
	register(s, "DeleteAuthorizer", s.deleteAuthorizer)
	register(s, "CreateRoute", s.createRoute)
	register(s, "GetRoute", s.getRoute)
	register(s, "GetRoutes", s.getRoutes)
	register(s, "UpdateRoute", s.updateRoute)
	register(s, "DeleteRoute", s.deleteRoute)
	register(s, "CreateRouteResponse", s.createRouteResponse)
	register(s, "GetRouteResponse", s.getRouteResponse)
	register(s, "GetRouteResponses", s.getRouteResponses)
	register(s, "UpdateRouteResponse", s.updateRouteResponse)
	register(s, "DeleteRouteResponse", s.deleteRouteResponse)
	register(s, "CreateStage", s.createStage)
	register(s, "GetStage", s.getStage)
	register(s, "GetStages", s.getStages)
	register(s, "UpdateStage", s.updateStage)
	register(s, "DeleteStage", s.deleteStage)
	register(s, "DeleteAccessLogSettings", s.deleteAccessLogSettings)
	register(s, "DeleteRouteSettings", s.deleteRouteSettings)
	register(s, "ResetAuthorizersCache", s.resetAuthorizersCache)
	register(s, "CreateDeployment", s.createDeployment)
	register(s, "GetDeployment", s.getDeployment)
	register(s, "GetDeployments", s.getDeployments)
	register(s, "UpdateDeployment", s.updateDeployment)
	register(s, "DeleteDeployment", s.deleteDeployment)
	register(s, "GetTags", s.getTags)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	registerDomains(s)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for n := range s.operations {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("apigatewayv2")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerErrorException", "Missing generated request binding", 500))
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
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func (s *Service) ExecuteCommand(ctx context.Context, in awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, in)
	fn, ok := s.operations[string(in.Operation.Name)]
	if !ok {
		// VPC links, models, imports and exports require actual execution
		// consumers before their configuration can be accepted.
		rejected := unsupported("This API Gateway V2 operation is not implemented")
		if err := s.RecordRequestError(ctx, in, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated request binding", 500)
		}
		var err error
		ctx, err = apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			tx, err = resourceOwnerTransaction(tx, action)
			if err != nil {
				return err
			}
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err == nil {
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
func (s *Service) RecordRequestError(ctx context.Context, in awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(in.Operation.Name), in.Input, nil, rejected)
}
func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	in, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("apigatewayv2")
	if awsapi.BindHTTP(model, operation, request, in) != nil {
		return nil
	}
	return in
}
func (s *Service) RequestError(_ string, err error) *awswire.Error {
	return failure("BadRequestException", err.Error(), 400)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) *awswire.Error { return failure("BadRequestException", message, 400) }
func unsupported(message string) *awswire.Error {
	return failure("NotImplementedException", message, 501)
}
func wireError(err error) *awswire.Error {
	if errors.Is(err, ErrNotFound) {
		return failure("NotFoundException", "Not Found", 404)
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message, 403)
		}
		return wire
	}
	return failure("InternalServerErrorException", "Unable to complete API Gateway operation", 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func boolean[T ~bool](p *T) bool      { return p != nil && bool(*p) }
func text[T ~string](p **T, v string) { *p = new(T(v)) }
func flag[T ~bool](p **T, v bool)     { *p = new(T(v)) }
func stringsOf[T ~string](v []T) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = string(x)
	}
	return out
}
func mapOf[K ~string, V ~string](v map[K]V) map[string]string {
	out := make(map[string]string, len(v))
	for k, x := range v {
		out[string(k)] = string(x)
	}
	return out
}
func stringList[S ~[]T, T ~string](p *S, v []string) {
	*p = make(S, len(v))
	for i, x := range v {
		(*p)[i] = T(x)
	}
}
func stringMap[M ~map[K]V, K ~string, V ~string](p *M, v map[string]string) {
	*p = make(M, len(v))
	for k, x := range v {
		(*p)[K(k)] = V(x)
	}
}
