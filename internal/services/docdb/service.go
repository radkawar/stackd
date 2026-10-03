package docdb

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	engine "stackd/engine/docdb"
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

const Namespace = "http://rds.amazonaws.com/doc/2014-10-31/"

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Runtime    engine.Runtime
	Cipher     CredentialCipher
	Names      NameOwner
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	runtime    engine.Runtime
	cipher     CredentialCipher
	names      NameOwner
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, cipher: c.Cipher, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.names = c.Names
	s.jobs = scheduler.New(c.Clock, clusterJobs{s}, snapshotJobs{s})
	register(s, "CreateDBCluster", s.createCluster)
	register(s, "DescribeDBClusters", s.describeClusters)
	register(s, "ModifyDBCluster", s.modifyCluster)
	register(s, "DeleteDBCluster", s.deleteCluster)
	register(s, "StartDBCluster", s.startCluster)
	register(s, "StopDBCluster", s.stopCluster)
	register(s, "CreateDBInstance", s.createInstance)
	register(s, "DescribeDBInstances", s.describeInstances)
	register(s, "DeleteDBInstance", s.deleteInstance)
	register(s, "RebootDBInstance", s.rebootInstance)
	register(s, "CreateDBClusterSnapshot", s.createSnapshot)
	register(s, "DescribeDBClusterSnapshots", s.describeSnapshots)
	register(s, "DeleteDBClusterSnapshot", s.deleteSnapshot)
	register(s, "RestoreDBClusterFromSnapshot", s.restoreCluster)
	register(s, "AddTagsToResource", s.addTags)
	register(s, "RemoveTagsFromResource", s.removeTags)
	register(s, "ListTagsForResource", s.listTags)
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
		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated request binding."))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), req)
	if e != nil {
		awswire.QueryError(w, r, Namespace, e)
		return
	}
	model, _ := awscatalog.LookupService("docdb")
	body, err := awsapi.EncodeResponse(model, req.Operation, out)
	if err != nil {
		awswire.QueryError(w, r, Namespace, wireError(err))
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, string(req.Operation.Name), body)
}

// TODO: Comeback implement DocumentDB managed networking/storage, distributed
// readers/failover, parameter groups, automated backups/PITR and remaining controls
// against real owners; the native backend is not the AWS DocumentDB storage engine.
func (s *Service) ExecuteCommand(ctx context.Context, req awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, req)
	if fn := s.operations[string(req.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	e := unsupported("The requested DocumentDB operation is not implemented.")
	if err := s.RecordRequestError(ctx, req, e); err != nil {
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
			e := wireError(err)
			completion, cancel := apievents.CompletionContext(ctx)
			defer cancel()
			if re := s.recordCall(completion, action, in, nil, e); re != nil {
				return nil, wireError(re)
			}
			return nil, e
		}
		s.jobs.Wake()
		return out, nil
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "Unknown DocumentDB operation.")
	}
	return failure("InvalidParameterValue", "The request parameters are invalid.")
}
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("docdb")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || action == "ListTagsForResource", Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"masterUserPassword": {Mode: awsapi.RedactValueField}, "preSignedUrl": {Mode: awsapi.RedactValueField}}}}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
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
	if code == "InternalFailure" {
		status = 500
	}
	if strings.Contains(code, "NotFound") {
		status = 404
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func unsupported(message string) *awswire.Error {
	return failure("InvalidParameterCombination", message)
}
func wireError(err error) *awswire.Error {
	var out *awswire.Error
	if errors.As(err, &out) {
		return out
	}
	return failure("InternalFailure", "Unable to complete the DocumentDB operation.")
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func yes[T ~bool](p *T) bool { return p != nil && bool(*p) }
