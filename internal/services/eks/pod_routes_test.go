package eks

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	native "stackd/compute/eks"
	"stackd/compute/network"
	"stackd/internal/awsctx"
)

type routeObservationRuntime struct {
	native.Runtime
	observe func(context.Context, native.Specification) ([]network.PodRoute, error)
}

func (r routeObservationRuntime) ObservePodRoutes(ctx context.Context, spec native.Specification) ([]network.PodRoute, error) {
	return r.observe(ctx, spec)
}

type routeObservationRepository struct {
	Repository
	viewing  bool
	views    int
	failView int
}

func (r *routeObservationRepository) View(ctx context.Context, fn func(Reader) error) error {
	r.views++
	if r.views == r.failView {
		return errors.New("current cluster authority unavailable")
	}
	r.viewing = true
	defer func() { r.viewing = false }()
	return r.Repository.View(ctx, fn)
}

func routeCluster() Cluster {
	return Cluster{Key: Key{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "pods"}, ID: "cluster-current", VPCID: "vpc-current", Status: "ACTIVE", Generation: 1}
}

func routeFixture(clusterID string) network.PodRoute {
	return network.PodRoute{Prefix: netip.MustParsePrefix("10.42.0.0/24"), ClusterID: clusterID, OwnerToken: "owner-current", NodeName: "worker-current", NodeUID: "node-uid-current", ResourceVersion: "17", ContainerID: "container-current", NetworkID: "network-current", WorkerIP: netip.MustParseAddr("172.22.0.3")}
}

func routeRequestContext(t *testing.T) context.Context {
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
}

func putRouteCluster(t *testing.T, repo Repository, cluster Cluster) {
	t.Helper()
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(cluster) }); err != nil {
		t.Fatal(err)
	}
}

func observeRoutes(s *Service, ctx context.Context) ([]network.PodRoute, error) {
	return s.PodRoutes(ctx, "aws", "111111111111", "us-east-1", "vpc-current")
}

func TestPodRoutesCurrentScopeDetachedAndOutsideTransactions(t *testing.T) {
	repo := &routeObservationRepository{Repository: NewMemoryRepository(nil)}
	cluster := routeCluster()
	putRouteCluster(t, repo, cluster)
	for _, foreign := range []Cluster{
		{Key: Key{Scope: cluster.Key.Scope, Name: "other-vpc"}, ID: "other-vpc", VPCID: "vpc-other", Status: "ACTIVE"},
		{Key: Key{Scope: Scope{"aws", "222222222222", "us-east-1"}, Name: "other-account"}, ID: "other-account", VPCID: cluster.VPCID, Status: "ACTIVE"},
		{Key: Key{Scope: Scope{"aws", "111111111111", "us-west-2"}, Name: "other-region"}, ID: "other-region", VPCID: cluster.VPCID, Status: "ACTIVE"},
	} {
		putRouteCluster(t, repo, foreign)
	}
	source := []network.PodRoute{routeFixture(cluster.ID)}
	calls := 0
	s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(ctx context.Context, spec native.Specification) ([]network.PodRoute, error) {
		calls++
		if repo.viewing || spec.ID != cluster.ID || spec.Region != cluster.Key.Region {
			t.Fatalf("observation crossed authority/transaction boundary: viewing=%t spec=%+v", repo.viewing, spec)
		}
		return source, nil
	}}}
	got, err := observeRoutes(s, routeRequestContext(t))
	if err != nil || !slices.Equal(got, source) || calls != 1 || repo.views != 2 {
		t.Fatalf("current routes: %+v calls=%d views=%d err=%v", got, calls, repo.views, err)
	}
	source[0].WorkerIP = netip.MustParseAddr("172.22.0.4")
	if got[0].WorkerIP == source[0].WorkerIP {
		t.Fatal("authority returned runtime-owned mutable slice")
	}
	next, err := observeRoutes(s, routeRequestContext(t))
	if err != nil || calls != 2 || next[0].WorkerIP != source[0].WorkerIP {
		t.Fatalf("previous observation was cached: %+v %v", next, err)
	}
}

func TestPodRoutesRejectsScopeUnavailableForeignAndOverlaps(t *testing.T) {
	for _, name := range []string{"scope", "observer-unavailable", "runtime-error", "foreign-cluster", "missing-owner", "missing-node", "missing-uid", "missing-version", "missing-container", "missing-network", "invalid-prefix", "unmasked-prefix", "invalid-next-hop", "recursive-next-hop", "duplicate", "overlap", "inactive", "current-read-error"} {
		t.Run(name, func(t *testing.T) {
			cluster := routeCluster()
			if name == "inactive" {
				cluster.Status = "DELETING"
			}
			repo := &routeObservationRepository{Repository: NewMemoryRepository(nil)}
			putRouteCluster(t, repo, cluster)
			if name == "current-read-error" {
				repo.failView = 2
			}
			route := routeFixture(cluster.ID)
			switch name {
			case "foreign-cluster":
				route.ClusterID = "replaced-cluster"
			case "missing-owner":
				route.OwnerToken = ""
			case "missing-node":
				route.NodeName = ""
			case "missing-uid":
				route.NodeUID = ""
			case "missing-version":
				route.ResourceVersion = ""
			case "missing-container":
				route.ContainerID = ""
			case "missing-network":
				route.NetworkID = ""
			case "invalid-prefix":
				route.Prefix = netip.Prefix{}
			case "unmasked-prefix":
				route.Prefix = netip.MustParsePrefix("10.42.0.8/24")
			case "invalid-next-hop":
				route.WorkerIP = netip.Addr{}
			case "recursive-next-hop":
				route.WorkerIP = netip.MustParseAddr("10.42.0.8")
			}
			s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(context.Context, native.Specification) ([]network.PodRoute, error) {
				if name == "runtime-error" {
					return nil, errors.New("native worker unavailable")
				}
				routes := []network.PodRoute{route}
				if name == "duplicate" || name == "overlap" {
					second := route
					second.NodeName = "second-worker"
					if name == "overlap" {
						second.Prefix = netip.MustParsePrefix("10.42.0.0/25")
					}
					routes = append(routes, second)
				}
				return routes, nil
			}}}
			if name == "observer-unavailable" {
				s.runtime = nil
			}
			ctx := routeRequestContext(t)
			if name == "scope" {
				ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"})
			}
			if routes, err := observeRoutes(s, ctx); err == nil || len(routes) != 0 {
				t.Fatalf("invalid authority returned usable routes: %+v %v", routes, err)
			}
		})
	}
}

func TestPodRoutesRejectsAuthorityChangedDuringObservation(t *testing.T) {
	for _, change := range []string{"replace", "move-vpc", "move-scope", "delete", "generation", "add"} {
		t.Run(change, func(t *testing.T) {
			repo := NewMemoryRepository(nil)
			cluster := routeCluster()
			putRouteCluster(t, repo, cluster)
			s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(ctx context.Context, _ native.Specification) ([]network.PodRoute, error) {
				err := repo.Update(ctx, func(tx Transaction) error {
					current := cluster
					switch change {
					case "replace":
						current.ID = "replacement"
					case "move-vpc":
						current.VPCID = "vpc-moved"
					case "move-scope":
						if err := tx.DeleteCluster(current.Key); err != nil {
							return err
						}
						current.Key.AccountID = "222222222222"
					case "delete":
						return tx.DeleteCluster(current.Key)
					case "generation":
						current.Generation++
					case "add":
						current.Key.Name = "added"
						current.ID = "added"
					}
					return tx.PutCluster(current)
				})
				if err != nil {
					return nil, err
				}
				return []network.PodRoute{routeFixture(cluster.ID)}, nil
			}}}
			if routes, err := observeRoutes(s, routeRequestContext(t)); err == nil || len(routes) != 0 {
				t.Fatalf("stale observation survived %s: %+v %v", change, routes, err)
			}
		})
	}
}

func TestPodRoutesRejectsCrossClusterOverlap(t *testing.T) {
	repo := NewMemoryRepository(nil)
	cluster := routeCluster()
	putRouteCluster(t, repo, cluster)
	second := cluster
	second.Key.Name = "second"
	second.ID = "second"
	putRouteCluster(t, repo, second)
	s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(_ context.Context, spec native.Specification) ([]network.PodRoute, error) {
		return []network.PodRoute{routeFixture(spec.ID)}, nil
	}}}
	if routes, err := observeRoutes(s, routeRequestContext(t)); err == nil || len(routes) != 0 {
		t.Fatalf("cross-cluster overlap admitted: %+v %v", routes, err)
	}
}

func TestPodRoutesNoRelevantClustersNeedsNoNativeObserver(t *testing.T) {
	repo := NewMemoryRepository(nil)
	cluster := routeCluster()
	cluster.VPCID = "vpc-unrelated"
	putRouteCluster(t, repo, cluster)
	s := &Service{repository: repo}
	if routes, err := observeRoutes(s, routeRequestContext(t)); err != nil || len(routes) != 0 {
		t.Fatalf("ordinary EC2 VPC requires native EKS observer: %+v %v", routes, err)
	}
}

func TestPodRoutesComposesDisjointClustersDeterministically(t *testing.T) {
	repo := NewMemoryRepository(nil)
	first := routeCluster()
	second := first
	second.Key.Name = "second"
	second.ID = "second"
	putRouteCluster(t, repo, second)
	putRouteCluster(t, repo, first)
	s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(_ context.Context, spec native.Specification) ([]network.PodRoute, error) {
		route := routeFixture(spec.ID)
		if spec.ID == first.ID {
			route.Prefix = netip.MustParsePrefix("10.42.2.0/24")
		}
		return []network.PodRoute{route}, nil
	}}}
	routes, err := observeRoutes(s, routeRequestContext(t))
	if err != nil || len(routes) != 2 || routes[0].ClusterID != second.ID || routes[1].ClusterID != first.ID {
		t.Fatalf("disjoint current clusters not composed in prefix order: %+v %v", routes, err)
	}
}

func TestPodRoutesRejectsAmbiguousClusterIdentity(t *testing.T) {
	repo := NewMemoryRepository(nil)
	first := routeCluster()
	second := first
	second.Key.Name = "second"
	putRouteCluster(t, repo, first)
	putRouteCluster(t, repo, second)
	s := &Service{repository: repo, runtime: routeObservationRuntime{observe: func(context.Context, native.Specification) ([]network.PodRoute, error) {
		t.Fatal("ambiguous cluster identity reached native observer")
		return nil, nil
	}}}
	if routes, err := observeRoutes(s, routeRequestContext(t)); err == nil || len(routes) != 0 {
		t.Fatalf("duplicate current cluster ID admitted: %+v %v", routes, err)
	}
}
