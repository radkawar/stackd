package opensearch

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
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

type Config struct {
	Repository     Repository
	Authorizer     authorization.Authorizer
	PolicyBinder   authorization.PolicyBinder
	Recorder       apievents.Recorder
	Clock          clock.Clock
	Runtime        Runtime
	Metrics        MetricPublisher
	PublicEndpoint string
	EndpointDomain string
}
type Service struct {
	repository     Repository
	authorizer     authorization.Authorizer
	binder         authorization.PolicyBinder
	recorder       apievents.Recorder
	clock          clock.Clock
	runtime        Runtime
	metrics        MetricPublisher
	endpoint       string
	endpointDomain string
	jobs           *scheduler.Driver
	operations     map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, metrics: c.Metrics, endpoint: strings.TrimRight(c.PublicEndpoint, "/"), operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.endpointDomain = c.EndpointDomain
	s.jobs = scheduler.New(c.Clock, domainJobs{s})
	register(s, "CreateDomain", s.createDomain)
	register(s, "DescribeDomain", s.describeDomain)
	register(s, "DescribeDomains", s.describeDomains)
	register(s, "DescribeDomainConfig", s.describeConfig)
	register(s, "UpdateDomainConfig", s.updateConfig)
	register(s, "DeleteDomain", s.deleteDomain)
	register(s, "ListDomainNames", s.listDomains)
	register(s, "ListVersions", s.listVersions)
	register(s, "AddTags", s.addTags)
	register(s, "RemoveTags", s.removeTags)
	register(s, "ListTags", s.listTags)
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
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

// TODO: Comeback implement managed multi-node/VPC/EBS/KMS/TLS/FGAC, snapshots,
// upgrades, packages, Dashboards and remaining OpenSearch control operations with
// real native owners. Unsupported effects are rejected, never retained inertly.
func (s *Service) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, r)
	if fn := s.operations[string(r.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	e := failure("ValidationException", "The requested OpenSearch operation is not supported.")
	if err := s.RecordRequestError(ctx, r, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	model, _ := awscatalog.LookupService("opensearch")
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx.Context(), tx, in)
			if e != nil {
				return e
			}
			return s.recordCall(tx.Context(), "opensearch", action, in, out, nil)
		})
		if err != nil {
			rejected := wireError(err)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if e := s.recordCall(completion, "opensearch", action, in, nil, rejected); e != nil {
				return nil, wireError(e)
			}
			return nil, rejected
		}
		s.jobs.Wake()
		return out, nil
	}
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("ValidationException", invalid.Error())
	}
	return failure("ValidationException", "Invalid OpenSearch request.")
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, "opensearch", string(r.Operation.Name), r.Input, nil, e)
}
func (s *Service) recordCall(ctx context.Context, service, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService(service)
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List"), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"advancedSecurityOptions.masterUserOptions.masterUserPassword": {Mode: awsapi.RedactValueField}}}}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	projectNativeAudit(&call, rejected)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
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
func enabled[T ~bool](v *T) bool { return v != nil && bool(*v) }
func failure(code, message string) *awswire.Error {
	status := 400
	switch code {
	case "ResourceNotFoundException":
		status = 404
	case "ResourceAlreadyExistsException":
		status = 409
	case "AccessDeniedException":
		status = 403
	case "InternalException":
		status = 500
	case "ServiceUnavailableException":
		status = 503
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			return failure("AccessDeniedException", e.Message)
		}
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Domain not found.")
	}
	return failure("InternalException", "Unable to complete the OpenSearch operation.")
}
