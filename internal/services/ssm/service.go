package ssm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Keys         DataKeys
	Events       Events
	Images       Images
	Secrets      Secrets
	Sharing      SharedParameters
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	binder     authorization.PolicyBinder
	recorder   apievents.Recorder
	clock      clock.Clock
	keys       DataKeys
	events     Events
	images     Images
	secrets    Secrets
	sharing    SharedParameters
	jobs       *scheduler.Driver
	tokenKey   [32]byte
	operations map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, keys: c.Keys, events: c.Events, images: c.Images, secrets: c.Secrets, sharing: c.Sharing, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	_, _ = rand.Read(s.tokenKey[:])
	s.jobs = scheduler.New(c.Clock, policyJobs{s}, imageJobs{s})
	register(s, "PutParameter", s.putParameter)
	register(s, "DeleteParameter", s.deleteParameter)
	register(s, "DeleteParameters", s.deleteParameters)
	register(s, "GetParameter", s.getParameter)
	register(s, "GetParameters", s.getParameters)
	register(s, "GetParametersByPath", s.getParametersByPath)
	register(s, "GetParameterHistory", s.getParameterHistory)
	register(s, "DescribeParameters", s.describeParameters)
	register(s, "LabelParameterVersion", s.labelParameterVersion)
	register(s, "UnlabelParameterVersion", s.unlabelParameterVersion)
	register(s, "AddTagsToResource", s.addTagsToResource)
	register(s, "RemoveTagsFromResource", s.removeTagsFromResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "GetServiceSetting", s.getServiceSetting)
	register(s, "UpdateServiceSetting", s.updateServiceSetting)
	register(s, "ResetServiceSetting", s.resetServiceSetting)
	register(s, "PutResourcePolicy", s.putResourcePolicy)
	register(s, "GetResourcePolicies", s.getResourcePolicies)
	register(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for action := range s.operations {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("ssm")
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerError", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	action := string(request.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// Fleet, RunCommand and Session Manager are separate SSM owners, not Parameter Store operations.
		rejected := failure("NotImplementedException", "SSM operation is not implemented: "+action)
		rejected.StatusCode = http.StatusNotImplemented
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
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
			return nil, failure("InternalServerError", "Missing generated request binding.")
		}
		return runCommand(s, ctx, action, in, fn)
	}
}
func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(Transaction, *I) (*O, error)) (*O, *awswire.Error) {
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
		return s.recordCall(tx.Context(), action, in, out, nil, true)
	})
	if err == nil {
		s.jobs.Wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, action, in, nil, rejected, true); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

// GetParameters is the ordinary authorized batch command used by execution-role consumers.
func (s *Service) GetParameters(ctx context.Context, in *api.GetParametersRequest) (*api.GetParametersResult, *awswire.Error) {
	return runCommand(s, ctx, "GetParameters", in, s.getParameters)
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected, false)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested SSM operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if invalid.TypeMismatch {
			return failure("SerializationException", invalid.Error())
		}
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServerError" {
		status = http.StatusInternalServerError
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
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
		return failure("ParameterNotFound", "Parameter not found.")
	}
	return failure("InternalServerError", "Unable to access Parameter Store state.")
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
