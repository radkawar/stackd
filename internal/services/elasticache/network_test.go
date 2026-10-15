package elasticache

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	"stackd/compute/network"
	engine "stackd/engine/valkey"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type placementRuntime struct {
	Runtime
	ensured, quarantined []engine.Specification
	deleted              []string
}

func (r *placementRuntime) Ensure(ctx context.Context, spec engine.Specification) (engine.Deployment, error) {
	r.ensured = append(r.ensured, spec)
	var deployment engine.Deployment
	for index, reservation := range spec.Networks {
		if _, err := spec.RefreshNetwork(ctx, index); err != nil {
			return deployment, err
		}
		deployment.Nodes = append(deployment.Nodes, engine.Node{ID: fmt.Sprintf("actual-%d", index), Shard: int32(index) / (spec.Replicas + 1), Replica: int32(index) % (spec.Replicas + 1), Endpoint: engine.Endpoint{Address: reservation.Network.Address.String(), Port: 6379}})
	}
	return deployment, nil
}
func (r *placementRuntime) Quarantine(ctx context.Context, spec engine.Specification) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.quarantined = append(r.quarantined, spec)
	return nil
}
func (r *placementRuntime) Delete(_ context.Context, id string) error {
	r.deleted = append(r.deleted, id)
	return nil
}

type placementNetworks struct {
	repository                 Repository
	cluster                    Cluster
	allocated, released        []CacheNodeNetworkIdentity
	observed                   []CacheNodeNetworkIdentity
	failAllocation             int
	observeError, releaseError error
	afterAllocate              func(context.Context, CacheNodeNetworkIdentity) error
	dns                        netip.Addr
}

func (n *placementNetworks) ResolveSubnets(context.Context, string, []string) ([]Subnet, error) {
	return []Subnet{{ID: "subnet-a", VPCID: "vpc-real", AvailabilityZone: "us-east-1a"}, {ID: "subnet-b", VPCID: "vpc-real", AvailabilityZone: "us-east-1b"}}, nil
}
func (n *placementNetworks) reservation(identity CacheNodeNetworkIdentity) CacheNodeNetwork {
	suffix := identity.NodeIndex - 1
	return CacheNodeNetwork{InterfaceID: fmt.Sprintf("eni-%d", identity.NodeIndex), SubnetID: []string{"subnet-a", "subnet-b"}[suffix%2], AvailabilityZone: []string{"us-east-1a", "us-east-1b"}[suffix%2], Network: network.Specification{NetworkID: "vpc-real", Pool: netip.MustParsePrefix("10.44.0.0/16"), Gateway: netip.MustParseAddr("10.44.0.1"), Address: netip.MustParseAddr(fmt.Sprintf("10.44.%d.10", suffix)), MAC: fmt.Sprintf("02:00:00:00:00:%02x", identity.NodeIndex), DNS: []netip.Addr{n.dns}}}
}
func (n *placementNetworks) nativeContext(ctx context.Context) error {
	metadata := awsctx.FromContext(ctx)
	if metadata.IssuerARN != "arn:aws:iam::111111111111:role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache" {
		return errors.New("native effect lost source role")
	}
	// A writable fresh transaction is unavailable inside the job's read-only view.
	return n.repository.Update(ctx, func(tx Transaction) error {
		row, err := tx.Cluster(n.cluster.Key)
		if err != nil {
			return err
		}
		return tx.PutCluster(row)
	})
}
func (n *placementNetworks) AllocateCacheNodeNetwork(ctx context.Context, request CacheNodeNetworkRequest) (CacheNodeNetwork, error) {
	if err := n.nativeContext(ctx); err != nil {
		return CacheNodeNetwork{}, err
	}
	n.allocated = append(n.allocated, request.Identity)
	if request.Identity.NodeIndex == n.failAllocation {
		return CacheNodeNetwork{}, errors.New("allocation unavailable")
	}
	if n.afterAllocate != nil {
		if err := n.afterAllocate(ctx, request.Identity); err != nil {
			return CacheNodeNetwork{}, err
		}
	}
	return n.reservation(request.Identity), nil
}
func (n *placementNetworks) ObserveCacheNodeNetwork(ctx context.Context, identity CacheNodeNetworkIdentity, id string) (CacheNodeNetwork, error) {
	if err := n.nativeContext(ctx); err != nil {
		return CacheNodeNetwork{}, err
	}
	n.observed = append(n.observed, identity)
	if n.observeError != nil {
		return CacheNodeNetwork{}, n.observeError
	}
	value := n.reservation(identity)
	if value.InterfaceID != id {
		return CacheNodeNetwork{}, errors.New("foreign interface")
	}
	return value, nil
}
func (n *placementNetworks) ReleaseCacheNodeNetwork(ctx context.Context, identity CacheNodeNetworkIdentity, _ string) error {
	if err := n.nativeContext(ctx); err != nil {
		return err
	}
	n.released = append(n.released, identity)
	return n.releaseError
}

type placementRoles struct {
	calls int
	err   error
}

func (r *placementRoles) EnsureServiceLinkedRole(_ context.Context, name string) error {
	if name != "elasticache.amazonaws.com" {
		return errors.New("wrong source service")
	}
	r.calls++
	return r.err
}

func placementService(t *testing.T) (*Service, *placementNetworks, *placementRuntime, Cluster, *clock.Manual) {
	t.Helper()
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	manual := clock.NewManual(now)
	row := Cluster{Key: Key{Scope: scopeFor(cacheContext(t.Context())), Kind: "replicationgroup", Name: "placed"}, RuntimeID: "old-incarnation", Engine: "valkey", EngineVersion: "8.1.6", NodeType: "cache.t4g.micro", MemoryBytes: 64 << 20, Shards: 1, Replicas: 1, TLSEnabled: true, SubnetGroup: "placed", ClientSubnets: []string{"subnet-a", "subnet-b"}, SecurityGroups: []string{"sg-real"}, ClientPort: 6379, Status: "creating", Operation: "create", Version: 1, Due: now}
	repo := NewMemoryRepository(nil)
	runtime := &placementRuntime{}
	networks := &placementNetworks{repository: repo, cluster: row, dns: netip.MustParseAddr("10.44.0.2")}
	s := New(Config{Repository: repo, Clock: manual, Runtime: runtime, Networks: networks, Roles: &placementRoles{}, Authorizer: &testAuthority{}})
	s.JobDriver().Close() // Explicitly drive jobs; no competing automatic after-commit job.
	t.Cleanup(func() { _ = s.Close() })
	if err := repo.Update(cacheContext(t.Context()), func(tx Transaction) error { return tx.PutCluster(row) }); err != nil {
		t.Fatal(err)
	}
	return s, networks, runtime, row, manual
}
func placementRow(t *testing.T, s *Service, key Key) Cluster {
	t.Helper()
	var row Cluster
	if err := s.repository.View(cacheContext(t.Context()), func(r Reader) error { var err error; row, err = r.Cluster(key); return err }); err != nil {
		t.Fatal(err)
	}
	return row
}
func drivePlacement(t *testing.T, s *Service, row Cluster) {
	t.Helper()
	if err := (clusterJobs{s}).Run(cacheContext(t.Context()), scheduler.Job{Key: row.Key.ARN(), Version: uint64(row.Version), Due: row.Due}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedPlacementCheckpointsPartialAllocationAndReusesOwnership(t *testing.T) {
	s, n, r, row, manual := placementService(t)
	n.failAllocation = 2
	drivePlacement(t, s, row)
	failed := placementRow(t, s, row.Key)
	if failed.Status == "available" || len(failed.NodePlacements) != 1 || len(r.ensured) != 0 || len(n.released) != 0 || len(r.quarantined) != 1 {
		t.Fatalf("partial allocation lost exact ownership or claimed readiness: %#v", failed)
	}
	n.failAllocation = 0
	manual.Advance(healthInterval)
	drivePlacement(t, s, failed)
	ready := placementRow(t, s, row.Key)
	if ready.Status != "available" || len(ready.NodePlacements) != 2 || len(r.ensured) != 1 {
		t.Fatalf("retained allocation did not recover: %#v", ready)
	}
	indices := []int{}
	for _, identity := range n.allocated {
		indices = append(indices, identity.NodeIndex)
		if identity.ClusterARN != row.Key.ARN() || identity.Incarnation != row.RuntimeID {
			t.Fatal("allocation lost immutable source")
		}
	}
	if !slices.Equal(indices, []int{1, 2, 2}) {
		t.Fatalf("reallocated retained first node: %v", indices)
	}
	primary := clusterOutput(Cluster{Key: ready.Key, Replicas: ready.Replicas, SubnetGroup: ready.SubnetGroup, SecurityGroups: ready.SecurityGroups, NodePlacements: ready.NodePlacements, Nodes: ready.Nodes[:1]}, true)
	if value(primary.PreferredAvailabilityZone) != "us-east-1a" || value(primary.CacheNodes[0].CustomerAvailabilityZone) != "us-east-1a" || value(primary.CacheSubnetGroupName) != "placed" {
		t.Fatalf("placement AZ was absent or fabricated: %#v", primary)
	}
	group := replicationOutput(ready)
	if value(group.NodeGroups[0].NodeGroupMembers[1].PreferredAvailabilityZone) != "us-east-1b" || value(group.NodeGroups[0].ReaderEndpoint.Address) == value(group.NodeGroups[0].PrimaryEndpoint.Address) || *group.NodeGroups[0].ReaderEndpoint.Port != 6379 {
		t.Fatal("reader did not retain distinct actual placement at configured port")
	}
	spec := r.ensured[0]
	n.dns = netip.MustParseAddr("10.44.0.53")
	fresh, err := spec.RefreshNetwork(managedRuntimeContext(cacheContext(t.Context()), ready), 0)
	if err != nil || len(fresh.Network.DNS) != 1 || fresh.Network.DNS[0] != n.dns {
		t.Fatalf("callback retained stale DHCP instead of reobserving: %v", err)
	}
}

func TestManagedPlacementObservationFailureQuarantinesWithoutDescribe(t *testing.T) {
	s, n, r, row, manual := placementService(t)
	drivePlacement(t, s, row)
	ready := placementRow(t, s, row.Key)
	n.observeError = errors.New("current EC2 observation denied")
	manual.Advance(healthInterval)
	drivePlacement(t, s, ready)
	failed := placementRow(t, s, row.Key)
	if failed.Status == "available" || len(failed.Nodes) != 0 || len(failed.NodePlacements) != 2 || len(r.ensured) != 1 || len(r.quarantined) != 1 {
		t.Fatalf("observation failure left old native readiness: %#v", failed)
	}
	quarantined := r.quarantined[0]
	if quarantined.ID != row.RuntimeID || quarantined.ClusterARN != row.Key.ARN() || len(quarantined.Networks) != 0 || quarantined.RefreshNetwork != nil {
		t.Fatal("quarantine depends on failed observation instead of retained immutable owner")
	}
	canceled, cancel := context.WithCancel(cacheContext(t.Context()))
	cancel()
	if err := s.quarantineManaged(canceled, row, n.observeError); !errors.Is(err, n.observeError) || len(r.quarantined) != 2 {
		t.Fatal("cancellation skipped bounded owned quarantine")
	}
}

func TestManagedPlacementDeleteDoesNotRequireObservationAndRetainsFailedRelease(t *testing.T) {
	s, n, r, row, _ := placementService(t)
	drivePlacement(t, s, row)
	ready := placementRow(t, s, row.Key)
	ready.Operation = "delete"
	ready.Status = "deleting"
	ready.Version++
	ready.Due = s.clock.Now()
	if err := s.repository.Update(cacheContext(t.Context()), func(tx Transaction) error { return tx.PutCluster(ready) }); err != nil {
		t.Fatal(err)
	}
	n.observeError = errors.New("EC2 observation unavailable")
	n.releaseError = errors.New("release unavailable")
	observed := len(n.observed)
	drivePlacement(t, s, ready)
	failed := placementRow(t, s, row.Key)
	if failed.Status != "deleting" || len(failed.NodePlacements) != 2 || len(n.observed) != observed || !slices.Equal(r.deleted, []string{row.RuntimeID}) {
		t.Fatalf("failed release discarded owner or depended on observation: %#v", failed)
	}
	n.releaseError = nil
	failed.Due = s.clock.Now()
	if err := s.repository.Update(cacheContext(t.Context()), func(tx Transaction) error { return tx.PutCluster(failed) }); err != nil {
		t.Fatal(err)
	}
	drivePlacement(t, s, failed)
	if err := s.repository.View(cacheContext(t.Context()), func(reader Reader) error {
		_, err := reader.Cluster(row.Key)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleted owner remains: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedPlacementLostIncarnationReleasesOnlyAllocatedOldOwner(t *testing.T) {
	s, n, r, row, _ := placementService(t)
	n.afterAllocate = func(ctx context.Context, _ CacheNodeNetworkIdentity) error {
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Cluster(row.Key)
			if err != nil {
				return err
			}
			current.RuntimeID = "replacement"
			current.Version++
			return tx.PutCluster(current)
		})
	}
	drivePlacement(t, s, row)
	replaced := placementRow(t, s, row.Key)
	if replaced.RuntimeID != "replacement" || len(replaced.NodePlacements) != 0 || len(n.released) != 1 || n.released[0].Incarnation != row.RuntimeID || len(r.ensured) != 0 {
		t.Fatal("stale allocation altered or removed replacement ownership")
	}
}

func TestManagedPlacementRoleUsageAndSubnetDeletionRetainFailedIntent(t *testing.T) {
	s, _, _, row, _ := placementService(t)
	ctx := cacheContext(t.Context())
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutSubnetGroup(SubnetGroup{Key: Key{Scope: row.Key.Scope, Kind: "subnetgroup", Name: row.SubnetGroup}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithElastiCacheRoleUsage(ctx, "aws", row.Key.AccountID, func(_ context.Context, resources []string) error {
		if !slices.Equal(resources, []string{row.Key.ARN()}) {
			t.Fatalf("creating role intent lost: %v", resources)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithElastiCacheRoleUsage(ctx, "aws", "222222222222", func(_ context.Context, resources []string) error {
		if len(resources) != 0 {
			t.Fatal("role usage crossed account")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.deleteSubnetGroup(ctx, tx, &api.DeleteCacheSubnetGroupMessage{CacheSubnetGroupName: new(api.String(row.SubnetGroup))})
		if err == nil {
			t.Fatal("in-use subnet group deleted")
		}
		return err
	}); err == nil {
		t.Fatal("in-use admission committed")
	}
}

type deniedPlacementRole struct {
	cause      error
	completed  bool
	repository Repository
	key        Key
}

func (e *deniedPlacementRole) Error() string { return e.cause.Error() }
func (e *deniedPlacementRole) Unwrap() error { return e.cause }
func (e *deniedPlacementRole) RecordRejection(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return e.repository.View(ctx, func(r Reader) error {
		_, err := r.Cluster(e.key)
		if !errors.Is(err, ErrNotFound) {
			return errors.New("child denial recorded before parent rollback")
		}
		e.completed = true
		return nil
	})
}
func TestManagedPlacementDeniedAutomaticRoleCompletesAfterRollback(t *testing.T) {
	s, n, r, row, _ := placementService(t)
	ctx := cacheContext(t.Context())
	key := Key{Scope: row.Key.Scope, Kind: "cluster", Name: "denied"}
	denied := &deniedPlacementRole{cause: failure("AccessDenied", "CreateServiceLinkedRole denied"), repository: s.repository, key: key}
	roles := &placementRoles{err: denied}
	s.roles = roles
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutSubnetGroup(SubnetGroup{Key: Key{Scope: row.Key.Scope, Kind: "subnetgroup", Name: row.SubnetGroup}, VPCID: "vpc-real", Subnets: []Subnet{{ID: "subnet-a", VPCID: "vpc-real", AvailabilityZone: "us-east-1a"}}})
	}); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("elasticache")
	operation, _ := model.Operation("CreateCacheCluster")
	_, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.CreateCacheClusterMessage{CacheClusterId: new(api.String(key.Name)), Engine: new(api.String("valkey")), EngineVersion: new(api.String("8.1")), CacheNodeType: new(api.String("cache.t4g.micro")), CacheSubnetGroupName: new(api.String(row.SubnetGroup)), SecurityGroupIds: api.SecurityGroupIdsList{api.String("sg-real")}, Port: new(api.IntegerOptional(6379)), TransitEncryptionEnabled: new(api.BooleanOptional(true))}})
	if rejected == nil || rejected.Code != "AccessDenied" || !denied.completed || roles.calls != 1 || len(n.allocated) != 0 || len(r.ensured) != 0 {
		t.Fatalf("automatic source-role denial lost rollback/completion or caused effects: %v", rejected)
	}
}
