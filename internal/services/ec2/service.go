package ec2

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"

	"stackd/clock"
	native "stackd/compute/ec2"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

const Namespace = "http://ec2.amazonaws.com/doc/2016-11-15/"

type AvailabilityZone struct{ Name, ID string }
type Config struct {
	Repository         Repository
	Authorizer         authorization.Authorizer
	Recorder           apievents.Recorder
	Clock              clock.Clock
	Regions            RegionAccess
	Snapshots          SnapshotControl
	Volumes            VolumeControl
	ImageSnapshots     ImageSnapshots
	InstanceRuntime    native.Executor
	InstanceVolumes    InstanceVolumes
	InstanceProfiles   InstanceProfiles
	InstanceIdentities InstanceIdentities
	InstanceTypes      InstanceTypes
	InstanceEvents     InstanceEvents
	InstanceImages     InstanceImageSnapshots
	InstanceMetrics    InstanceMetrics
	SharedSubnets      SharedSubnetAccess
}
type Service struct {
	repository          Repository
	authorizer          authorization.Authorizer
	recorder            apievents.Recorder
	clock               clock.Clock
	regions             RegionAccess
	snapshots           SnapshotControl
	volumes             VolumeControl
	imageSnapshots      ImageSnapshots
	instanceRuntime     native.Executor
	instanceVolumes     InstanceVolumes
	instanceProfiles    InstanceProfiles
	instanceIdentities  InstanceIdentities
	instanceTypes       InstanceTypes
	instanceEvents      InstanceEvents
	instanceImages      InstanceImageSnapshots
	instanceMetrics     InstanceMetrics
	sharedSubnets       SharedSubnetAccess
	instanceWorkMu      sync.Mutex
	identitySigningMu   sync.Mutex
	identitySigningKeys map[string]*instanceIdentitySigner
	instanceHandles     map[ResourceKey]native.Instance
	jobs                *scheduler.Driver
	operations          map[string]func(context.Context) (any, *awswire.Error)
}
type emptyResult = api.Unit

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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, regions: c.Regions, snapshots: c.Snapshots, volumes: c.Volumes, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.imageSnapshots = c.ImageSnapshots
	s.instanceRuntime, s.instanceVolumes, s.instanceProfiles = c.InstanceRuntime, c.InstanceVolumes, c.InstanceProfiles
	s.instanceIdentities = c.InstanceIdentities
	s.instanceTypes, s.instanceEvents, s.instanceImages = c.InstanceTypes, c.InstanceEvents, c.InstanceImages
	s.instanceMetrics = c.InstanceMetrics
	s.sharedSubnets = c.SharedSubnets
	if s.instanceTypes == nil {
		s.instanceTypes = s
	}
	s.jobs = scheduler.New(c.Clock, computeJobs{s})
	register(s, "CreateVpc", s.createVPC)
	register(s, "DescribeVpcs", s.describeVPCs)
	register(s, "DeleteVpc", s.deleteVPC)
	register(s, "DescribeVpcAttribute", s.describeVPCAttribute)
	register(s, "ModifyVpcAttribute", s.modifyVPCAttribute)
	register(s, "CreateSubnet", s.createSubnet)
	register(s, "DescribeSubnets", s.describeSubnets)
	register(s, "DeleteSubnet", s.deleteSubnet)
	register(s, "ModifySubnetAttribute", s.modifySubnetAttribute)
	register(s, "CreateTags", s.createTags)
	register(s, "DeleteTags", s.deleteTags)
	register(s, "DescribeTags", s.describeTags)
	registerSecurityGroups(s)
	registerRouting(s)
	registerInternetGateways(s)
	registerNetworkInterfaces(s)
	registerPublicAddresses(s)
	registerNetworkOwners(s)
	registerDHCPOptions(s)
	registerAvailability(s)
	registerKeyPairs(s)
	registerSnapshots(s)
	registerVolumes(s)
	registerImages(s)
	registerInstanceTypes(s)
	registerInstances(s)
	registerInstanceCredits(s)
	registerInstanceProfiles(s)
	registerInstanceImages(s)
	registerLaunchTemplates(s)
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
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		params, err := awswire.ParseQuery(r, awscatalog.EC2Query)
		if err != nil {
			rejected := awswire.QueryInputError(awscatalog.EC2Query, err)
			model, _ := awscatalog.LookupService("ec2")
			if op, known := model.Operation(r.Form.Get("Action")); known {
				if e := s.RecordRequestError(r.Context(), awsapi.DecodedRequest{Operation: op}, rejected); e != nil {
					rejected = wireError(e)
				}
			}
			awswire.EC2QueryError(w, r, rejected)
			return
		}
		decoded, err = api.DecodeRequest(params.Get("Action"), awsapi.Request{Query: params})
		if err != nil {
			rejected := s.RequestError(params.Get("Action"), err)
			if decoded.Operation.Name != "" {
				if e := s.RecordRequestError(r.Context(), decoded, rejected); e != nil {
					rejected = wireError(e)
				}
			}
			awswire.EC2QueryError(w, r, rejected)
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), decoded))
	}
	action := string(decoded.Operation.Name)
	out, rejected := s.ExecuteCommand(r.Context(), decoded)
	if rejected != nil {
		awswire.EC2QueryError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ec2")
	body, err := awsapi.EncodeResponse(model, decoded.Operation, out)
	if err != nil {
		awswire.EC2QueryError(w, r, wireError(err))
		return
	}
	awswire.WriteEC2QueryBytes(w, r, Namespace, action, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement the remaining EC2 networking and compute
		// operations; recognized unsupported requests still produce audit events.
		rejected := unsupported("Operation is not implemented: " + action)
		if err := s.recordCall(ctx, action, decoded.Input, nil, rejected); err != nil {
			rejected = wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, &awswire.Error{Code: "InternalError", Message: "Missing generated EC2 request binding.", StatusCode: 500}
		}
		if s.recorder != nil {
			ctx = WithSnapshotAudit(ctx)
			var err error
			ctx, err = apievents.Reserve(ctx)
			if err != nil {
				return nil, wireError(err)
			}
		}
		ctx, outcomes := apievents.RetainOutcomes(ctx)
		var out *O
		// Consumers such as Auto Scaling handle DryRunOperation as admission
		// success; a rejected EC2 child must not poison their outer transaction.
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			owned, admission, err := beginCloudFormationOwner(tx.Context(), tx)
			if err != nil {
				return err
			}
			out, err = fn(owned.Context(), owned, in)
			if err != nil {
				return err
			}
			// Private CloudFormation claims commit atomically with the native
			// effect, after the command has evaluated current IAM.
			if err := admission.finish(owned.Context()); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		})
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.repository.Update(completion, func(tx Transaction) error {
			if err := outcomes.Record(tx.Context()); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, nil, rejected)
		}); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	return awswire.QueryInputError(awscatalog.EC2Query, err)
}
func failure(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
func unsupported(message string) *awswire.Error {
	return &awswire.Error{Code: "UnsupportedOperation", Message: message, StatusCode: 400}
}
func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return &awswire.Error{Code: "UnauthorizedOperation", Message: wire.Message, StatusCode: 403}
		}
		return wire
	}
	return &awswire.Error{Code: "InternalError", Message: "Unable to access EC2 state.", StatusCode: 500}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func key(ctx context.Context, id string) ResourceKey { return ResourceKey{scopeFor(ctx), id} }
func str[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func boolValue(v *api.Boolean) bool { return v != nil && bool(*v) }
func resourceARN(scope Scope, kind, id string) string {
	if kind == "snapshot" || kind == "image" {
		return "arn:" + scope.Partition + ":ec2:" + scope.Region + "::" + kind + "/" + id
	}
	return "arn:" + scope.Partition + ":ec2:" + scope.Region + ":" + scope.AccountID + ":" + kind + "/" + id
}
func dryRun(v *api.Boolean) error {
	if boolValue(v) {
		return &awswire.Error{Code: "DryRunOperation", Message: "Request would have succeeded, but DryRun flag is set.", StatusCode: 412}
	}
	return nil
}
func (s *Service) authorize(ctx context.Context, action, kind, id string, tags api.TagList) error {
	return s.authorizeWith(ctx, action, kind, id, tags, nil)
}
func (s *Service) authorizeWith(ctx context.Context, action, kind, id string, tags api.TagList, conditions map[string][]string) error {
	owner := scopeFor(ctx).AccountID
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for _, t := range tags {
		conditions["aws:ResourceTag/"+str(t.Key)] = []string{str(t.Value)}
		conditions["ec2:ResourceTag/"+str(t.Key)] = []string{str(t.Value)}
	}
	conditions["ec2:Region"] = []string{scopeFor(ctx).Region}
	addLaunchTemplateConditions(ctx, action, kind, id, conditions)
	addLambdaManagedLaunchConditions(ctx, action, kind, conditions)
	arn := "*"
	if kind != "" && kind != "*" {
		arn = resourceARN(scopeFor(ctx), kind, id)
	} else {
		owner = ""
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "ec2:" + action, ResourceARN: arn, ResourceAccountID: owner, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}

func vpcConditions(scope Scope, id string) map[string][]string {
	if id == "" {
		return nil
	}
	return map[string][]string{"ec2:Vpc": {resourceARN(scope, "vpc", id)}}
}
func (s *Service) authorizeCreate(ctx context.Context, action, kind, id string, tags api.TagList) error {
	return s.authorizeCreateWith(ctx, action, kind, id, tags, nil)
}

func (s *Service) authorizeCreateWith(ctx context.Context, action, kind, id string, tags api.TagList, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for _, tag := range tags {
		conditions["aws:RequestTag/"+str(tag.Key)] = []string{str(tag.Value)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], str(tag.Key))
	}
	if err := s.authorizeWith(ctx, action, kind, id, nil, conditions); err != nil {
		return err
	}
	if len(tags) > 0 {
		conditions["ec2:CreateAction"] = []string{action}
		return s.authorizeWith(ctx, "CreateTags", kind, id, nil, conditions)
	}
	return nil
}
