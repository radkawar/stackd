package rds

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"stackd/clock"
	engine "stackd/engine/rds"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

const Namespace = "http://rds.amazonaws.com/doc/2014-10-31/"

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Runtime    engine.Runtime
	Cipher     CredentialCipher
	Networks   NetworkControl
	Events     EventPublisher
	Metrics    MetricPublisher
	DocumentDB DocumentDB
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	runtime    engine.Runtime
	cipher     CredentialCipher
	networks   NetworkControl
	events     EventPublisher
	metrics    MetricPublisher
	documents  DocumentDB
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, cipher: c.Cipher, networks: c.Networks, events: c.Events, metrics: c.Metrics, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.documents = c.DocumentDB
	s.jobs = scheduler.New(c.Clock, databaseJobs{s}, snapshotJobs{s})
	register(s, "CreateDBInstance", s.createInstance)
	register(s, "DescribeDBInstances", s.describeInstances)
	register(s, "ModifyDBInstance", s.modifyInstance)
	register(s, "StartDBInstance", s.startInstance)
	register(s, "StopDBInstance", s.stopInstance)
	register(s, "DeleteDBInstance", s.deleteInstance)
	register(s, "RebootDBInstance", s.rebootInstance)
	register(s, "CreateDBCluster", s.createCluster)
	register(s, "DescribeDBClusters", s.describeClusters)
	register(s, "ModifyDBCluster", s.modifyCluster)
	register(s, "StartDBCluster", s.startCluster)
	register(s, "StopDBCluster", s.stopCluster)
	register(s, "DeleteDBCluster", s.deleteCluster)
	register(s, "EnableHttpEndpoint", s.enableHTTP)
	register(s, "DisableHttpEndpoint", s.disableHTTP)
	register(s, "CreateDBSnapshot", s.createSnapshot)
	register(s, "DescribeDBSnapshots", s.describeSnapshots)
	register(s, "DeleteDBSnapshot", s.deleteSnapshot)
	register(s, "RestoreDBInstanceFromDBSnapshot", s.restoreInstance)
	register(s, "CreateDBClusterSnapshot", s.createClusterSnapshot)
	register(s, "DescribeDBClusterSnapshots", s.describeClusterSnapshots)
	register(s, "DeleteDBClusterSnapshot", s.deleteClusterSnapshot)
	register(s, "RestoreDBClusterFromSnapshot", s.restoreCluster)
	register(s, "CreateDBParameterGroup", s.createParameterGroup)
	register(s, "DescribeDBParameterGroups", s.describeParameterGroups)
	register(s, "ModifyDBParameterGroup", s.modifyParameterGroup)
	register(s, "ResetDBParameterGroup", s.resetParameterGroup)
	register(s, "DeleteDBParameterGroup", s.deleteParameterGroup)
	register(s, "DescribeDBParameters", s.describeParameters)
	register(s, "CreateDBClusterParameterGroup", s.createClusterParameterGroup)
	register(s, "DescribeDBClusterParameterGroups", s.describeClusterParameterGroups)
	register(s, "ModifyDBClusterParameterGroup", s.modifyClusterParameterGroup)
	register(s, "ResetDBClusterParameterGroup", s.resetClusterParameterGroup)
	register(s, "DeleteDBClusterParameterGroup", s.deleteClusterParameterGroup)
	register(s, "DescribeDBClusterParameters", s.describeClusterParameters)
	register(s, "CreateDBSubnetGroup", s.createSubnetGroup)
	register(s, "ModifyDBSubnetGroup", s.modifySubnetGroup)
	register(s, "DescribeDBSubnetGroups", s.describeSubnetGroups)
	register(s, "DeleteDBSubnetGroup", s.deleteSubnetGroup)
	register(s, "AddTagsToResource", s.addTags)
	register(s, "RemoveTagsFromResource", s.removeTags)
	register(s, "ListTagsForResource", s.listTags)
	register(s, "DescribeDBEngineVersions", s.describeEngineVersions)
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

func (s *Service) JobDriver() *scheduler.Driver {
	return s.jobs
}

func (s *Service) Close() error {
	s.jobs.Close()
	return nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {

		awswire.QueryError(w, r, Namespace, failure("InternalFailure", "Missing generated request binding."))
		return

	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {

		awswire.QueryError(w, r, Namespace, rejected)
		return

	}
	model, _ := awscatalog.LookupService("rds")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {

		awswire.QueryError(w, r, Namespace, wireError(err))
		return

	}
	awswire.WriteQueryBytes(w, r, Namespace, string(request.Operation.Name), body)
}

// TODO: Comeback implement remaining RDS topology, managed storage, networking,
// automated backups, maintenance, replication, IAM database authentication,
// managed password rotation and proxy controls with real owners.
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	if s.documents != nil {
		if out, handled, rejected := s.documents.ExecuteRDS(ctx, request); handled {
			return out, rejected
		}
	}
	if fn := s.operations[string(request.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	rejected := unsupported("The requested RDS operation is not implemented.")
	if err := s.RecordRequestError(ctx, request, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
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
		if needsObservation(action) {
			err = s.observeScope(ctx)
		}
		var out *O
		if err == nil {
			err = s.repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				out, err = fn(tx.Context(), tx, in)
				if err != nil {
					return err
				}
				if s.documents != nil {
					if err := s.documents.CheckCreate(tx.Context(), in); err != nil {
						return err
					}
				}
				return s.recordCall(tx.Context(), action, in, out, nil)
			})
		}
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

func needsObservation(action string) bool {
	switch action {
	case "DescribeDBInstances", "DescribeDBClusters", "ModifyDBInstance", "ModifyDBCluster", "StopDBInstance", "StopDBCluster", "CreateDBSnapshot", "CreateDBClusterSnapshot", "RebootDBInstance":
		return true
	}
	return false
}

func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}

func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "Unknown RDS operation.")
	}
	return failure("InvalidParameterValue", "The request parameters are invalid.")
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("rds")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	readOnly := false
	switch action {
	case "DescribeDBInstances", "DescribeDBClusters", "DescribeDBSnapshots", "DescribeDBClusterSnapshots", "DescribeDBParameterGroups", "DescribeDBClusterParameterGroups", "DescribeDBParameters", "DescribeDBClusterParameters", "DescribeDBSubnetGroups", "DescribeDBEngineVersions", "ListTagsForResource":
		readOnly = true
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly, Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"masterUserPassword": {Mode: awsapi.RedactValueField}, "tdeCredentialPassword": {Mode: awsapi.RedactValueField}, "preSignedUrl": {Mode: awsapi.RedactValueField}, "parameters.parameterValue": {Mode: awsapi.RedactValueField}}}}
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
	switch code {
	case "InternalFailure":
		status = 500
	case "DBInstanceNotFound", "DBClusterNotFoundFault", "DBSnapshotNotFound",
		"DBClusterSnapshotNotFoundFault", "DBParameterGroupNotFound", "DBSubnetGroupNotFoundFault":
		status = 404
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
	if errors.Is(err, ErrNotFound) {
		return failure("DBInstanceNotFound", "The requested RDS resource does not exist.")
	}
	return failure("InternalFailure", "Unable to complete the RDS operation.")
}

func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

func boolean[T ~bool](v *T) bool {
	return v != nil && bool(*v)
}
