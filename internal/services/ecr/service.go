package ecr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
)

type Config struct {
	Repository       Repository
	Authorizer       authorization.Authorizer
	PolicyBinder     authorization.PolicyBinder
	Recorder         apievents.Recorder
	Events           EventPublisher
	Clock            clock.Clock
	PublicEndpoint   string
	Keys             DataKeys
	Scanner          Scanner
	ReplicationRoles ReplicationRoles
}
type Service struct {
	repository       Repository
	authorizer       authorization.Authorizer
	binder           authorization.PolicyBinder
	recorder         apievents.Recorder
	events           EventPublisher
	clock            clock.Clock
	endpoint         string
	keys             DataKeys
	scanner          Scanner
	replicationRoles ReplicationRoles
	jobs             *scheduler.Driver
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
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, events: c.Events, clock: c.Clock, endpoint: strings.TrimRight(c.PublicEndpoint, "/"), keys: c.Keys, scanner: c.Scanner, replicationRoles: c.ReplicationRoles, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, lifecycleJobs{s}, scanningJobs{s}, replicationJobs{s})
	register(s, "CreateRepository", s.createRepository)
	register(s, "DeleteRepository", s.deleteRepository)
	register(s, "DescribeRepositories", s.describeRepositories)
	register(s, "DescribeRegistry", s.describeRegistry)
	register(s, "GetAuthorizationToken", s.getAuthorizationToken)
	register(s, "SetRepositoryPolicy", s.setRepositoryPolicy)
	register(s, "GetRepositoryPolicy", s.getRepositoryPolicy)
	register(s, "DeleteRepositoryPolicy", s.deleteRepositoryPolicy)
	register(s, "PutRegistryPolicy", s.putRegistryPolicy)
	register(s, "GetRegistryPolicy", s.getRegistryPolicy)
	register(s, "DeleteRegistryPolicy", s.deleteRegistryPolicy)
	register(s, "PutImageTagMutability", s.putImageTagMutability)
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "PutImage", s.putImage)
	register(s, "BatchGetImage", s.batchGetImage)
	register(s, "BatchDeleteImage", s.batchDeleteImage)
	register(s, "DescribeImages", s.describeImages)
	register(s, "ListImages", s.listImages)
	register(s, "InitiateLayerUpload", s.initiateLayerUpload)
	register(s, "UploadLayerPart", s.uploadLayerPart)
	register(s, "CompleteLayerUpload", s.completeLayerUpload)
	register(s, "BatchCheckLayerAvailability", s.batchCheckLayerAvailability)
	register(s, "GetDownloadUrlForLayer", s.getDownloadURLForLayer)
	register(s, "PutReplicationConfiguration", s.putReplicationConfiguration)
	register(s, "DescribeImageReplicationStatus", s.describeImageReplicationStatus)
	register(s, "PutLifecyclePolicy", s.putLifecyclePolicy)
	register(s, "GetLifecyclePolicy", s.getLifecyclePolicy)
	register(s, "DeleteLifecyclePolicy", s.deleteLifecyclePolicy)
	register(s, "StartLifecyclePolicyPreview", s.startLifecyclePolicyPreview)
	register(s, "GetLifecyclePolicyPreview", s.getLifecyclePolicyPreview)
	register(s, "BatchGetRepositoryScanningConfiguration", s.batchGetRepositoryScanningConfiguration)
	register(s, "GetRegistryScanningConfiguration", s.getRegistryScanningConfiguration)
	register(s, "PutRegistryScanningConfiguration", s.putRegistryScanningConfiguration)
	register(s, "PutImageScanningConfiguration", s.putImageScanningConfiguration)
	register(s, "StartImageScan", s.startImageScan)
	register(s, "DescribeImageScanFindings", s.describeImageScanFindings)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("ServerException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ecr")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	name := string(request.Operation.Name)
	fn, ok := s.operations[name]
	if !ok {
		e := failure("UnsupportedOperationException", "Private ECR operation is not implemented: "+name)
		if err := s.RecordRequestError(ctx, request, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
	return fn(ctx)
}
func register[I, O any](s *Service, name string, fn func(Transaction, *I) (*O, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("ServerException", "Missing generated request binding.")
		}
		return runCommand(s, ctx, name, in, fn)
	}
}
func runCommand[I, O any](s *Service, ctx context.Context, name string, in *I, fn func(Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		tx = bindCloudFormationOwnership(tx)
		var err error
		out, err = fn(tx, in)
		if err != nil {
			return err
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
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown private ECR operation.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		return failure("InvalidParameterException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ecr")
	op, ok := model.Operation(name)
	if !ok {
		return nil
	}
	p := auditProjection(name)
	call, err := p.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	call.EventResources = auditRepositoryResources(scope, in)
	if rejected != nil && rejected.Code == "AccessDeniedException" {
		call.ErrorCode = "AccessDenied"
		call.RequestParameters = nil
	}
	if rejected != nil && rejected.Code == "InvalidParameterException" && (name == "SetRepositoryPolicy" || name == "PutLifecyclePolicy") {
		call.RequestParameters = nil
		call.EventResources = nil
	}
	if name == "BatchGetImage" && call.RequestParameters != nil {
		if err := auditBatchGetImageRequest(&call); err != nil {
			return err
		}
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func (s *Service) recordServiceEvent(ctx context.Context, name string, repo RepositoryRecord, detail any) error {
	if s.recorder == nil {
		return nil
	}
	m := awsctx.Metadata{Partition: repo.Key.Partition, AccountID: repo.Key.AccountID, Region: repo.Key.Region, ParentEventID: apievents.EventID(ctx), ServicePrincipal: awsctx.ServicePrincipal{Name: "ecr.amazonaws.com", SourceARN: repo.ARN, Type: "AWSService"}}
	ctx, err := apievents.Reserve(awsctx.WithMetadata(ctx, m))
	if err != nil {
		return err
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, journal.APICallCompleted{EventID: apievents.EventID(ctx), EventSource: "ecr.amazonaws.com", EventName: name, Category: journal.CategoryManagement, ServiceEvent: true, AdditionalEventData: body})
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "ServerException" {
		status = 500
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
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
		return failure("RepositoryNotFoundException", "The specified repository does not exist.")
	}
	return failure("ServerException", "Unable to access private ECR state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func str[T ~string](v string) *T { return new(T(v)) }
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
func (s *Service) origin() (string, error) {
	u, err := url.Parse(s.endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", failure("ServerException", "ECR requires PublicEndpoint to be the reachable stack HTTP origin.")
	}
	return u.Scheme + "://" + u.Host, nil
}
