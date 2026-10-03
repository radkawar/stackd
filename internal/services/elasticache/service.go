package elasticache

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
)

const Namespace = "http://elasticache.amazonaws.com/doc/2015-02-02/"

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Runtime    Runtime
	Networks   NetworkControl
	Events     EventPublisher
	Metrics    MetricPublisher
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	runtime    Runtime
	networks   NetworkControl
	events     EventPublisher
	metrics    MetricPublisher
	jobs       *scheduler.Driver
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, networks: c.Networks, events: c.Events, metrics: c.Metrics, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.jobs = scheduler.New(c.Clock, clusterJobs{s}, snapshotJobs{s})
	register(s, "CreateCacheCluster", s.createCluster)
	register(s, "DescribeCacheClusters", s.describeClusters)
	register(s, "ModifyCacheCluster", s.modifyCluster)
	register(s, "DeleteCacheCluster", s.deleteCluster)
	register(s, "RebootCacheCluster", s.rebootCluster)
	register(s, "CreateReplicationGroup", s.createReplicationGroup)
	register(s, "DescribeReplicationGroups", s.describeReplicationGroups)
	register(s, "ModifyReplicationGroup", s.modifyReplicationGroup)
	register(s, "DeleteReplicationGroup", s.deleteReplicationGroup)
	register(s, "CreateUser", s.createUser)
	register(s, "ModifyUser", s.modifyUser)
	register(s, "DescribeUsers", s.describeUsers)
	register(s, "DeleteUser", s.deleteUser)
	register(s, "CreateUserGroup", s.createUserGroup)
	register(s, "ModifyUserGroup", s.modifyUserGroup)
	register(s, "DescribeUserGroups", s.describeUserGroups)
	register(s, "DeleteUserGroup", s.deleteUserGroup)
	register(s, "CreateCacheParameterGroup", s.createParameterGroup)
	register(s, "DescribeCacheParameterGroups", s.describeParameterGroups)
	register(s, "DescribeCacheParameters", s.describeParameters)
	register(s, "ModifyCacheParameterGroup", s.modifyParameterGroup)
	register(s, "ResetCacheParameterGroup", s.resetParameterGroup)
	register(s, "DeleteCacheParameterGroup", s.deleteParameterGroup)
	register(s, "CreateCacheSubnetGroup", s.createSubnetGroup)
	register(s, "ModifyCacheSubnetGroup", s.modifySubnetGroup)
	register(s, "DescribeCacheSubnetGroups", s.describeSubnetGroups)
	register(s, "DeleteCacheSubnetGroup", s.deleteSubnetGroup)
	register(s, "AddTagsToResource", s.addTags)
	register(s, "RemoveTagsFromResource", s.removeTags)
	register(s, "ListTagsForResource", s.listTags)
	register(s, "CreateSnapshot", s.createSnapshot)
	register(s, "DescribeSnapshots", s.describeSnapshots)
	register(s, "CopySnapshot", s.copySnapshot)
	register(s, "DeleteSnapshot", s.deleteSnapshot)
	register(s, "DescribeCacheEngineVersions", s.describeEngineVersions)
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
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated request."))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), req)
	if e != nil {
		awswire.QueryError(w, r, Namespace, e)
		return
	}
	model, _ := awscatalog.LookupService("elasticache")
	body, err := awsapi.EncodeResponse(model, req.Operation, out)
	if err != nil {
		awswire.QueryError(w, r, Namespace, wireError(err))
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, string(req.Operation.Name), body)
}

// TODO: Comeback add serverless, online resharding, global replication, managed
// maintenance, automated backups, IAM engine auth, KMS and VPC enforcement with
// their actual owners. Unsupported effects are rejected, never metadata claims.
func (s *Service) ExecuteCommand(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, req)
	if fn := s.operations[string(req.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	e := unsupported("This ElastiCache operation is not implemented.")
	if err := s.RecordRequestError(ctx, req, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated input.")
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
		s.jobs.Wake()
		return out, nil
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error {
	if errors.Is(e, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "Unknown ElastiCache operation.")
	}
	return failure("InvalidParameterValue", "Invalid request parameters.")
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("elasticache")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || action == "ListTagsForResource", Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"AuthToken": {Mode: awsapi.RedactValueField}, "Passwords": {Mode: awsapi.RedactField}, "AuthenticationMode.Passwords": {Mode: awsapi.RedactField}}}}
	// Exact-ID native management captures in testdata/aws/valkey establish
	// response presence independently from write/read classification.
	switch action {
	case "CreateUser", "ModifyUser", "DeleteUser", "ModifyCacheParameterGroup", "ResetCacheParameterGroup":
		p.Response = &awsapi.DocumentProjection{}
	case "CreateCacheParameterGroup":
		if result, ok := out.(*api.CreateCacheParameterGroupResult); ok && result != nil {
			op.Output = "com.amazonaws.elasticache#CacheParameterGroup"
			out = result.CacheParameterGroup
			p.Response = &awsapi.DocumentProjection{}
		}
	}
	in = auditInput(in)
	call, e := p.Call(model, op, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := 400
	switch code {
	case "InternalFailure":
		status = 500
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func unsupported(message string) *awswire.Error {
	return failure("InvalidParameterCombination", message)
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var out *awswire.Error
	if errors.As(err, &out) {
		return out
	}
	return failure("InternalFailure", "Unable to complete the ElastiCache operation.")
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func boolean[T ~bool](p *T) bool { return p != nil && bool(*p) }
func integer[T ~int32](p *T, fallback int32) int32 {
	if p == nil {
		return fallback
	}
	return int32(*p)
}
