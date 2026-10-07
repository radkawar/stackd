package memorydb

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
)

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
	register(s, "CreateCluster", s.createCluster)
	register(s, "DescribeClusters", s.describeClusters)
	register(s, "UpdateCluster", s.updateCluster)
	register(s, "DeleteCluster", s.deleteCluster)
	register(s, "CreateUser", s.createUser)
	register(s, "DescribeUsers", s.describeUsers)
	register(s, "UpdateUser", s.updateUser)
	register(s, "DeleteUser", s.deleteUser)
	register(s, "CreateACL", s.createACL)
	register(s, "DescribeACLs", s.describeACLs)
	register(s, "UpdateACL", s.updateACL)
	register(s, "DeleteACL", s.deleteACL)
	register(s, "CreateParameterGroup", s.createParameterGroup)
	register(s, "DescribeParameterGroups", s.describeParameterGroups)
	register(s, "UpdateParameterGroup", s.updateParameterGroup)
	register(s, "ResetParameterGroup", s.resetParameterGroup)
	register(s, "DeleteParameterGroup", s.deleteParameterGroup)
	register(s, "DescribeParameters", s.describeParameters)
	register(s, "CreateSubnetGroup", s.createSubnetGroup)
	register(s, "DescribeSubnetGroups", s.describeSubnetGroups)
	register(s, "UpdateSubnetGroup", s.updateSubnetGroup)
	register(s, "DeleteSubnetGroup", s.deleteSubnetGroup)
	register(s, "CreateSnapshot", s.createSnapshot)
	register(s, "DescribeSnapshots", s.describeSnapshots)
	register(s, "DeleteSnapshot", s.deleteSnapshot)
	register(s, "CopySnapshot", s.copySnapshot)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTags", s.listTags)
	register(s, "DescribeEngineVersions", s.describeEngineVersions)
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
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalFailure", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("memorydb")
	body, e := awsapi.EncodeResponse(model, request.Operation, out)
	if e != nil {
		awswire.JSONError(w, r, wireError(e))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// TODO: Comeback implement managed network attachment, KMS at-rest encryption,
// automatic snapshots, maintenance, resharding, multi-region, failover controls,
// SNS notifications and IAM data authentication through their real owners.
func (s *Service) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, r)
	if fn := s.operations[string(r.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	e := unsupported("This MemoryDB operation is not implemented.")
	if err := s.RecordRequestError(ctx, r, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated request binding.")
		}
		ctx, e := apievents.Reserve(ctx)
		if e != nil {
			return nil, wireError(e)
		}
		var out *O
		e = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, err = fn(tx.Context(), bindCloudFormationOwner(tx), in)
			if err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if e != nil {
			rejected := wireError(e)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
				return nil, wireError(err)
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
		return failure("InvalidAction", "Unknown MemoryDB operation.")
	}
	return invalid("The request parameters are invalid.")
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("memorydb")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List"), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"AuthenticationMode.Passwords": {Mode: awsapi.RedactField}}}}
	switch action {
	case "CreateUser", "UpdateUser", "DeleteUser", "CreateParameterGroup", "UpdateParameterGroup", "ResetParameterGroup", "DeleteParameterGroup":
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, e := projection.Call(model, op, auditInput(in), out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}

// auditInput retains the server-expanded request fields observed in exact-ID
// native management events without changing caller input or command admission.
func auditInput(in any) any {
	switch input := in.(type) {
	case *api.DescribeUsersRequest:
		if input != nil && input.MaxResults == nil {
			copy := *input
			copy.MaxResults = new(api.IntegerOptional(50))
			return &copy
		}
	case *api.DescribeParametersRequest:
		if input != nil && input.MaxResults == nil {
			copy := *input
			copy.MaxResults = new(api.IntegerOptional(100))
			return &copy
		}
	case *api.DescribeParameterGroupsRequest:
		if input != nil && input.MaxResults == nil {
			copy := *input
			copy.MaxResults = new(api.IntegerOptional(100))
			return &copy
		}
	case *api.DescribeEngineVersionsRequest:
		if input != nil {
			copy := *input
			if copy.MaxResults == nil {
				copy.MaxResults = new(api.IntegerOptional(100))
			}
			if value(copy.Engine) == "valkey" {
				copy.Engine = new(api.String("durable_valkey"))
			}
			return &copy
		}
	}
	return in
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := 400
	if code == "InternalFailure" {
		status = 500
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error {
	return failure("InvalidParameterValueException", message)
}
func unsupported(message string) *awswire.Error {
	return failure("InvalidParameterCombinationException", message)
}
func wireError(e error) *awswire.Error {
	var out *awswire.Error
	if errors.As(e, &out) {
		return out
	}
	return failure("InternalFailure", "Unable to complete the MemoryDB operation.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func truth[T ~bool](v *T) bool { return v != nil && bool(*v) }
func (s *Service) ensureRuntime() error {
	if s.runtime == nil {
		return unsupported("A native Valkey runtime is required.")
	}
	return nil
}
