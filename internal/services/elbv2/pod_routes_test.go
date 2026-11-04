package elbv2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/elbv2"
	"stackd/compute/network"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
)

// These boundary fixtures observe actual service reconciliation and retained
// health state, not native packet delivery (covered by the compute runtime).
type podPolicyRepository struct {
	Repository
	inside bool
}

func (r *podPolicyRepository) View(ctx context.Context, fn func(Reader) error) error {
	r.inside = true
	defer func() { r.inside = false }()
	return r.Repository.View(ctx, fn)
}

func (r *podPolicyRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	r.inside = true
	defer func() { r.inside = false }()
	return r.Repository.Update(ctx, fn)
}

type podPolicyNetworks struct {
	NetworkAuthority
	t          *testing.T
	repository *podPolicyRepository
	attachment NetworkAttachment
	routes     []network.PodRoute
	routeErr   error
	calls      int
}

func (n *podPolicyNetworks) PodRoutes(ctx context.Context, scope Scope, vpc string) ([]network.PodRoute, error) {
	n.t.Helper()
	n.calls++
	metadata := awsctx.FromContext(ctx)
	if n.repository.inside || vpc != "vpc-current" || scope.Partition != metadata.Partition || scope.AccountID != metadata.AccountID || scope.Region != metadata.Region {
		n.t.Fatalf("pod observation crossed transaction/scope boundary: inside=%t scope=%+v vpc=%s", n.repository.inside, scope, vpc)
	}
	return n.routes, n.routeErr
}

func (n *podPolicyNetworks) Allocate(_ context.Context, _ Scope, _, subnet string, _ uint64, _ bool, _ []string) (NetworkAttachment, error) {
	out := n.attachment
	out.ID = "eni-" + subnet
	out.SubnetID = subnet
	return out, nil
}

func (n *podPolicyNetworks) Observe(_ context.Context, _ Scope, _, id string) (NetworkAttachment, error) {
	out := n.attachment
	out.ID = id
	return out, nil
}

func (n *podPolicyNetworks) SetSecurityGroups(ctx context.Context, scope Scope, owner, id string, _ []string) (NetworkAttachment, error) {
	return n.Observe(ctx, scope, owner, id)
}

type podPolicyNode struct {
	policies []network.Policy
	closed   bool
	install  func(network.Policy) error
}

func (n *podPolicyNode) Listen(context.Context, int) (net.Listener, error) {
	return nil, errors.New("unexpected listener in policy-only fixture")
}

func (n *podPolicyNode) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected socket in policy-only fixture")
}

func (n *podPolicyNode) SetNetworkPolicy(_ context.Context, policy network.Policy) error {
	if n.install != nil {
		if err := n.install(policy); err != nil {
			return err
		}
	}
	policy.PodRoutes = slices.Clone(policy.PodRoutes)
	n.policies = append(n.policies, policy)
	return nil
}

func (n *podPolicyNode) Close() error { n.closed = true; return nil }

type podPolicyRuntime struct {
	native.Runtime
	nodes   map[string]*podPolicyNode
	prepare func(native.Specification) error
}

func (r *podPolicyRuntime) Prepare(_ context.Context, spec native.Specification) (native.Node, error) {
	if r.prepare != nil {
		if err := r.prepare(spec); err != nil {
			return nil, err
		}
	}
	node := r.nodes[spec.AttachmentID]
	if node == nil {
		node = &podPolicyNode{}
		r.nodes[spec.AttachmentID] = node
	}
	return node, nil
}

func podPolicyRoute() network.PodRoute {
	return network.PodRoute{Prefix: netip.MustParsePrefix("10.42.0.0/24"), ClusterID: "cluster-current", OwnerToken: "owner", NodeName: "node", NodeUID: "uid", ResourceVersion: "17", ContainerID: "container", NetworkID: "network", WorkerIP: netip.MustParseAddr("172.22.0.3")}
}

func podPolicyFixture(t *testing.T) (*Service, *podPolicyNetworks, *podPolicyRuntime, LoadBalancerRecord) {
	t.Helper()
	repo := &podPolicyRepository{Repository: NewMemoryRepository(nil)}
	networks := &podPolicyNetworks{t: t, repository: repo, routes: []network.PodRoute{podPolicyRoute()}, attachment: NetworkAttachment{Network: network.Specification{
		Address: netip.MustParseAddr("10.0.0.8"), Gateway: netip.MustParseAddr("10.0.0.1"), Pool: netip.MustParsePrefix("10.0.0.0/24"),
		Policy: network.Policy{Subnet: netip.MustParsePrefix("10.0.0.0/24"), SecurityEgress: []network.IPRule{{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}}, ACLIngress: []network.ACLRule{{Number: 100, Allow: true}}, PublicIPv4: netip.MustParseAddr("198.51.100.8"), PublicEgress: true},
	}}}
	runtime := &podPolicyRuntime{nodes: map[string]*podPolicyNode{}}
	s := New(Config{Repository: repo, Clock: clock.NewManual(time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)), Networks: networks, Runtime: runtime})
	// No listeners are retained in this policy-only reconciliation fixture.
	s.dnsAttached = true
	t.Cleanup(func() { _ = s.Close() })
	lb := LoadBalancerRecord{Scope: Scope{"aws", "111111111111", "us-east-1"}, Version: 1, IdleTimeout: time.Minute, Data: api.LoadBalancer{
		LoadBalancerArn: new(api.LoadBalancerArn("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/pods/current")), VpcId: new(api.VpcId("vpc-current")), Scheme: new(api.LoadBalancerSchemeEnum("internal")), SecurityGroups: api.SecurityGroups{"sg-current"}, AvailabilityZones: api.AvailabilityZones{{SubnetId: new(api.SubnetId("subnet-a"))}},
	}}
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutLoadBalancer(lb) }); err != nil {
		t.Fatal(err)
	}
	return s, networks, runtime, lb
}

func reconcilePodPolicy(t *testing.T, s *Service, lb LoadBalancerRecord) LoadBalancerRecord {
	t.Helper()
	if err := s.repository.View(t.Context(), func(tx Reader) error {
		var err error
		lb, err = tx.LoadBalancer(lb.Scope, value(lb.Data.LoadBalancerArn))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.runtime.reconcileLoadBalancer(t.Context(), value(lb.Data.LoadBalancerArn), lb.NextReconcile, lb.Version); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(t.Context(), func(tx Reader) error {
		var err error
		lb, err = tx.LoadBalancer(lb.Scope, value(lb.Data.LoadBalancerArn))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return lb
}

func TestPodRouteObserverFailureRevokesRoutesAndInstallsCurrentSG(t *testing.T) {
	s, networks, runtime, lb := podPolicyFixture(t)
	lb = reconcilePodPolicy(t, s, lb)
	node := runtime.nodes["eni-subnet-a"]
	if len(node.policies) != 1 || !slices.Equal(node.policies[0].PodRoutes, networks.routes) {
		t.Fatalf("initial pod authority not installed with base policy: %+v", node.policies)
	}
	// The observer returns its previous snapshot alongside an error; neither it
	// nor the previously permissive SG may survive the next current revision.
	networks.routeErr = errors.New("current worker authority unavailable")
	networks.attachment.Network.Policy.SecurityEgress = nil
	networks.attachment.Network.Policy.PublicEgress = false
	lb = reconcilePodPolicy(t, s, lb)
	latest := node.policies[len(node.policies)-1]
	if !latest.Equal(networks.attachment.Network.Policy) || len(latest.PodRoutes) != 0 || node.closed {
		t.Fatalf("authority failure retained stale routes/SG or closed ordinary path: %+v closed=%t", latest, node.closed)
	}
	if value(lb.Data.State.Code) != "active_impaired" || value(lb.Data.State.Reason) == "" || networks.calls != 2 {
		t.Fatalf("authority failure not reported independently: %+v calls=%d", lb.Data.State, networks.calls)
	}
	// Recovery installs a replacement tuple rather than resurrecting the old
	// route owner, and an empty current observation withdraws it again.
	networks.routeErr = nil
	networks.routes[0].WorkerIP = netip.MustParseAddr("172.22.0.4")
	networks.routes[0].NodeUID = "replacement-uid"
	lb = reconcilePodPolicy(t, s, lb)
	if latest = node.policies[len(node.policies)-1]; !slices.Equal(latest.PodRoutes, networks.routes) || value(lb.Data.State.Code) != "active" {
		t.Fatalf("replacement authority not refreshed: %+v %+v", latest, lb.Data.State)
	}
	networks.routes = nil
	lb = reconcilePodPolicy(t, s, lb)
	if latest = node.policies[len(node.policies)-1]; len(latest.PodRoutes) != 0 || !latest.Equal(networks.attachment.Network.Policy) || node.closed || networks.calls != 4 {
		t.Fatalf("empty current observation cached routes/disrupted EC2: %+v calls=%d", latest, networks.calls)
	}
}

func TestPodRouteAbsentAuthorityPreservesOrdinaryCurrentEC2Policy(t *testing.T) {
	s, networks, runtime, lb := podPolicyFixture(t)
	networks.routes = nil
	lb = reconcilePodPolicy(t, s, lb)
	node := runtime.nodes["eni-subnet-a"]
	if len(node.policies) != 1 || !node.policies[0].Equal(networks.attachment.Network.Policy) || value(lb.Data.State.Code) != "active" || node.closed {
		t.Fatalf("ordinary EC2 policy changed without relevant EKS routes: %+v %+v", node.policies, lb.Data.State)
	}
}

func TestPodRouteInstallRaceRetriesCurrentBasePolicy(t *testing.T) {
	for _, phase := range []string{"prepare", "update"} {
		t.Run(phase, func(t *testing.T) {
			s, networks, runtime, lb := podPolicyFixture(t)
			prepareCalls := 0
			if phase == "prepare" {
				runtime.prepare = func(spec native.Specification) error {
					prepareCalls++
					if len(spec.Network.Policy.PodRoutes) != 0 {
						return &network.PodRouteInstallError{Err: errors.New("worker disappeared before prepare")}
					}
					return nil
				}
			} else {
				lb = reconcilePodPolicy(t, s, lb)
				runtime.nodes["eni-subnet-a"].install = func(policy network.Policy) error {
					if len(policy.PodRoutes) != 0 {
						return &network.PodRouteInstallError{Err: errors.New("worker disappeared before update")}
					}
					return nil
				}
			}
			networks.attachment.Network.Policy.SecurityEgress = nil
			lb = reconcilePodPolicy(t, s, lb)
			node := runtime.nodes["eni-subnet-a"]
			latest := node.policies[len(node.policies)-1]
			if !latest.Equal(networks.attachment.Network.Policy) || node.closed || value(lb.Data.State.Code) != "active_impaired" {
				t.Fatalf("pod route race did not preserve current EC2 policy: %+v closed=%t state=%+v", latest, node.closed, lb.Data.State)
			}
			if phase == "prepare" && prepareCalls != 2 {
				t.Fatalf("prepare did not retry exact base policy: calls=%d", prepareCalls)
			}
		})
	}
}

func TestPodRouteInstallRaceRevokesEarlierNodesInSameCycle(t *testing.T) {
	s, networks, runtime, lb := podPolicyFixture(t)
	lb.Data.AvailabilityZones = append(lb.Data.AvailabilityZones, api.AvailabilityZone{SubnetId: new(api.SubnetId("subnet-b"))})
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutLoadBalancer(lb) }); err != nil {
		t.Fatal(err)
	}
	lb = reconcilePodPolicy(t, s, lb)
	runtime.nodes["eni-subnet-b"].install = func(policy network.Policy) error {
		if len(policy.PodRoutes) != 0 {
			return &network.PodRouteInstallError{Err: errors.New("worker changed after first AZ install")}
		}
		return nil
	}
	networks.attachment.Network.Policy.SecurityEgress = nil
	lb = reconcilePodPolicy(t, s, lb)
	for id, node := range runtime.nodes {
		latest := node.policies[len(node.policies)-1]
		if !latest.Equal(networks.attachment.Network.Policy) || node.closed {
			t.Fatalf("%s retained revoked pod authority or stale SG: %+v closed=%t", id, latest, node.closed)
		}
	}
	if value(lb.Data.State.Code) != "active_impaired" {
		t.Fatalf("lost worker authority not diagnosed: %+v", lb.Data.State)
	}
}

func TestPodRouteBasePolicyFailureRetainsNativeFailClosedBehavior(t *testing.T) {
	s, networks, runtime, lb := podPolicyFixture(t)
	lb = reconcilePodPolicy(t, s, lb)
	node := runtime.nodes["eni-subnet-a"]
	node.install = func(policy network.Policy) error {
		if len(policy.PodRoutes) != 0 {
			return &network.PodRouteInstallError{Err: errors.New("worker unavailable")}
		}
		return errors.New("current base EC2 policy cannot be enforced")
	}
	networks.attachment.Network.Policy.SecurityEgress = nil
	lb = reconcilePodPolicy(t, s, lb)
	if !node.closed || len(s.runtime.nodes[value(lb.Data.LoadBalancerArn)]) != 0 || value(lb.Data.State.Code) != "active_impaired" {
		t.Fatalf("unenforceable base policy left node serving: closed=%t state=%+v", node.closed, lb.Data.State)
	}
}
