package eks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	native "stackd/compute/eks"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
)

// Authenticator verifies the original presigned STS request without network forwarding.
type Authenticator func(*http.Request, string, string) (*http.Request, *awswire.Error)
type Config struct {
	Repository          Repository
	Authorizer          authorization.Authorizer
	Recorder            apievents.Recorder
	Clock               clock.Clock
	Runtime             native.Runtime
	Authenticator       Authenticator
	Networks            Networks
	Principals          Principals
	Nodegroups          NodegroupCompute
	WorkloadRoles       WorkloadRoles
	Logs                ControlPlaneLogs
	Audit               KubernetesAuditObserver
	NodeNames           EKSNodeNames
	PodIdentityRoles    PodIdentityRoles
	ServiceLinkedRoles  ServiceLinkedRoles
	PodIdentityEndpoint string
}
type Service struct {
	repository          Repository
	authorizer          authorization.Authorizer
	recorder            apievents.Recorder
	clock               clock.Clock
	runtime             native.Runtime
	authenticate        Authenticator
	networks            Networks
	principals          Principals
	nodegroups          NodegroupCompute
	workloadRoles       WorkloadRoles
	logs                ControlPlaneLogs
	audit               KubernetesAuditObserver
	nodeNames           EKSNodeNames
	podIdentityRoles    PodIdentityRoles
	serviceLinkedRoles  ServiceLinkedRoles
	podIdentityEndpoint string
	jobs                *scheduler.Driver
	effects             *clusterEffects
	operations          map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, runtime: c.Runtime, authenticate: c.Authenticator, networks: c.Networks, principals: c.Principals, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.nodegroups = c.Nodegroups
	s.workloadRoles = c.WorkloadRoles
	s.logs = c.Logs
	s.audit = c.Audit
	s.nodeNames = c.NodeNames
	s.podIdentityRoles = c.PodIdentityRoles
	s.serviceLinkedRoles = c.ServiceLinkedRoles
	s.podIdentityEndpoint = c.PodIdentityEndpoint
	s.effects = newClusterEffects()
	s.jobs = scheduler.New(c.Clock, clusterJobs{s})
	register(s, "CreateCluster", s.createCluster)
	register(s, "DescribeCluster", s.describeCluster)
	register(s, "ListClusters", s.listClusters)
	register(s, "DeleteCluster", s.deleteCluster)
	register(s, "UpdateClusterConfig", s.updateClusterConfig)
	register(s, "UpdateClusterVersion", s.updateClusterVersion)
	register(s, "DescribeUpdate", s.describeUpdate)
	register(s, "ListUpdates", s.listUpdates)
	register(s, "CreateAccessEntry", s.createAccessEntry)
	register(s, "DescribeAccessEntry", s.describeAccessEntry)
	register(s, "UpdateAccessEntry", s.updateAccessEntry)
	register(s, "DeleteAccessEntry", s.deleteAccessEntry)
	register(s, "ListAccessEntries", s.listAccessEntries)
	register(s, "AssociateAccessPolicy", s.associateAccessPolicy)
	register(s, "DisassociateAccessPolicy", s.disassociateAccessPolicy)
	register(s, "ListAssociatedAccessPolicies", s.listAssociatedAccessPolicies)
	register(s, "ListAccessPolicies", s.listAccessPolicies)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTags)
	registerNodegroups(s)
	registerPodIdentity(s)
	registerAddons(s)
	registerFargate(s)
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
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("ServerException", "Missing generated request", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("eks")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

// TODO: Comeback implement native EventBridge lifecycle notifications once their
// payload contract is captured, plus external clusters and native AWS VPC endpoints.
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	e := unsupported("This EKS operation is not implemented by the selected Kubernetes runtime.")
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, action string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("ServerException", "Missing generated input", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = f(tx.Context(), tx, in)
			if e != nil {
				return e
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
		if e := s.recordCall(completion, action, in, nil, rejected); e != nil {
			return nil, wireError(e)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("eks")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List")}
	query, _ := in.(*api.ListAccessPoliciesRequest)
	projectedInput := in
	if query != nil {
		projectedInput = nil
	}
	call, e := p.Call(model, op, projectedInput, out, rejected)
	if e != nil {
		return e
	}
	if query != nil {
		// Native audit retains query numbers as strings, not decoded JSON numbers.
		call.RequestParameters, e = json.Marshal(struct {
			MaxResults *api.ListAccessPoliciesRequestMaxResults `json:"maxResults,omitempty,string"`
			NextToken  *api.String                              `json:"nextToken,omitempty"`
		}{query.MaxResults, query.NextToken})
		if e != nil {
			return e
		}
	}
	if action == "DescribeCluster" && rejected != nil && rejected.Code == "ResourceNotFoundException" {
		call.ErrorMessage = ""
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func (s *Service) authorize(ctx context.Context, c Cluster, action string, conditions map[string][]string) error {
	resource := c.Key.ARN()
	if action == "ListClusters" || action == "ListAccessPolicies" {
		resource = "*"
	}
	return s.authorizeResource(ctx, resource, c.Tags, action, conditions)
}
func (s *Service) authorizeResource(ctx context.Context, resource string, tags map[string]string, action string, conditions map[string][]string) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: "eks:" + action, ResourceARN: resource, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}
func (s *Service) load(ctx context.Context, r Reader, name, action string) (Cluster, error) {
	k := Key{scopeFor(ctx), name}
	c, e := r.Cluster(k)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return c, e
	}
	if errors.Is(e, ErrNotFound) {
		c.Key = k
	}
	if denied := s.authorize(ctx, c, action, nil); denied != nil {
		return c, denied
	}
	return c, e
}
func failure(c, m string, status int) *awswire.Error {
	return &awswire.Error{Code: c, Message: m, StatusCode: status}
}
func invalid(m string) *awswire.Error     { return failure("InvalidParameterException", m, 400) }
func unsupported(m string) *awswire.Error { return failure("InvalidRequestException", m, 400) }
func wireError(e error) *awswire.Error {
	var w *awswire.Error
	if errors.As(e, &w) {
		return w
	}
	if errors.Is(e, ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested EKS resource does not exist.", 404)
	}
	return failure("ServerException", "Unable to complete the EKS operation.", 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
