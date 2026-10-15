package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
	msk "stackd/internal/services/kafka"
)

type joinedStatusContext struct {
	context.Context
	reached chan struct{}
	once    sync.Once
}

func (c *joinedStatusContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.reached) })
	return c.Context.Done()
}
func statusTestSpec() msk.Specification {
	return msk.Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", Brokers: 1, KafkaVersion: "3.7.1", SecurityMode: "SASL_SCRAM", Users: []msk.SCRAMUser{{Username: "consumer", Password: "original"}}, Networks: []msk.BrokerNetwork{{InterfaceID: "eni-owned", SubnetID: "subnet-owned", AvailabilityZone: "us-east-1a", Network: network.Specification{NetworkID: "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-owned", Pool: netip.MustParsePrefix("10.4.0.0/16"), Gateway: netip.MustParseAddr("10.4.0.1"), Address: netip.MustParseAddr("10.4.0.4"), MAC: "02:00:00:00:00:04", DNS: []netip.Addr{netip.MustParseAddr("10.4.0.2")}, DNSSupport: true, Policy: network.Policy{Subnet: netip.MustParsePrefix("10.4.0.0/24")}}}}}
}
func awaitStatus(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("bounded status did not finish")
		return nil
	}
}
func awaitStatusJoin(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("caller did not join blocked observation")
	}
}

func TestOverlappingStatusCoalescesProofButRechecksEachCaller(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1)}
	spec := statusTestSpec()
	var authority, physical atomic.Int32
	spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) { authority.Add(1); return spec.Networks[0], nil }
	entered, release := make(chan struct{}), make(chan struct{})
	observe := func(ctx context.Context, current msk.Specification) (msk.Endpoint, error) {
		physical.Add(1)
		_, err := current.RefreshNetwork(ctx, 0)
		close(entered)
		<-release
		return msk.Endpoint{SecurityMode: "SASL_SCRAM"}, err
	}
	leader := make(chan error, 1)
	go func() { _, err := d.status(t.Context(), spec, observe); leader <- err }()
	awaitStatusJoin(t, entered)
	const callers = 6
	joined := make([]*joinedStatusContext, callers)
	results := make([]chan error, callers)
	for i := range callers {
		joined[i] = &joinedStatusContext{Context: t.Context(), reached: make(chan struct{})}
		results[i] = make(chan error, 1)
		go func(i int) { _, err := d.status(joined[i], spec, observe); results[i] <- err }(i)
		awaitStatusJoin(t, joined[i].reached)
	}
	close(release)
	if err := awaitStatus(t, leader); err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if err := awaitStatus(t, result); err != nil {
			t.Fatal(err)
		}
	}
	if physical.Load() != 1 || authority.Load() != callers+1 {
		t.Fatalf("physical=%d authority=%d", physical.Load(), authority.Load())
	}
	d.statusMu.Lock()
	defer d.statusMu.Unlock()
	if len(d.statusFlights) != 0 {
		t.Fatal("completed proof remained cached")
	}
}

func TestJoinedStatusCancellationDoesNotCancelValidLeader(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1)}
	spec := statusTestSpec()
	spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) { return spec.Networks[0], nil }
	entered, release := make(chan struct{}), make(chan struct{})
	observe := func(ctx context.Context, current msk.Specification) (msk.Endpoint, error) {
		_, err := current.RefreshNetwork(ctx, 0)
		close(entered)
		<-release
		return msk.Endpoint{}, err
	}
	leader := make(chan error, 1)
	go func() { _, err := d.status(t.Context(), spec, observe); leader <- err }()
	awaitStatusJoin(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	joined := &joinedStatusContext{Context: ctx, reached: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := d.status(joined, spec, observe); result <- err }()
	awaitStatusJoin(t, joined.reached)
	cancel()
	if err := awaitStatus(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellable joined wait: %v", err)
	}
	select {
	case err := <-leader:
		t.Fatalf("joined cancellation affected valid leader: %v", err)
	default:
	}
	close(release)
	if err := awaitStatus(t, leader); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledLeaderAllowsOneFreshIndependentProof(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1)}
	spec := statusTestSpec()
	spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) { return spec.Networks[0], nil }
	entered := make(chan struct{})
	var proofs atomic.Int32
	observe := func(ctx context.Context, current msk.Specification) (msk.Endpoint, error) {
		if proofs.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return msk.Endpoint{}, ctx.Err()
		}
		_, err := current.RefreshNetwork(ctx, 0)
		return msk.Endpoint{}, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	leader := make(chan error, 1)
	go func() { _, err := d.status(ctx, spec, observe); leader <- err }()
	awaitStatusJoin(t, entered)
	joined := &joinedStatusContext{Context: t.Context(), reached: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := d.status(joined, spec, observe); result <- err }()
	awaitStatusJoin(t, joined.reached)
	cancel()
	if err := awaitStatus(t, leader); !errors.Is(err, context.Canceled) {
		t.Fatalf("leader cancellation=%v", err)
	}
	if err := awaitStatus(t, result); err != nil {
		t.Fatal(err)
	}
	if proofs.Load() != 2 {
		t.Fatalf("independent proof count=%d", proofs.Load())
	}
}

func TestCurrentPolicyAndDHCPChangeRequireNewPhysicalProof(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "security-group", true: "dhcp"}[dhcp], func(t *testing.T) {
			d := &Docker{gate: make(chan struct{}, 1)}
			spec := statusTestSpec()
			var changed atomic.Bool
			var proofs atomic.Int32
			spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) {
				current := cloneObservedNetwork(spec.Networks[0].Network)
				if changed.Load() {
					if dhcp {
						current.DNS = []netip.Addr{netip.MustParseAddr("fd00::53")}
					} else {
						current.Policy.SecurityIngress = []network.IPRule{{CIDR: netip.MustParsePrefix("10.4.0.0/16"), Protocol: 6, FromPort: 9096, ToPort: 9096}}
					}
				}
				result := spec.Networks[0]
				result.Network = current
				return result, nil
			}
			entered, release := make(chan struct{}), make(chan struct{})
			observe := func(ctx context.Context, current msk.Specification) (msk.Endpoint, error) {
				count := proofs.Add(1)
				_, err := current.RefreshNetwork(ctx, 0)
				if count == 1 {
					close(entered)
					<-release
				}
				return msk.Endpoint{}, err
			}
			leader := make(chan error, 1)
			go func() { _, err := d.status(t.Context(), spec, observe); leader <- err }()
			awaitStatusJoin(t, entered)
			joined := &joinedStatusContext{Context: t.Context(), reached: make(chan struct{})}
			result := make(chan error, 1)
			go func() { _, err := d.status(joined, spec, observe); result <- err }()
			awaitStatusJoin(t, joined.reached)
			changed.Store(true)
			close(release)
			if err := awaitStatus(t, leader); err != nil {
				t.Fatal(err)
			}
			if err := awaitStatus(t, result); err != nil {
				t.Fatal(err)
			}
			if proofs.Load() != 2 {
				t.Fatalf("changed current policy reused old proof: %d", proofs.Load())
			}
		})
	}
}

func TestJoinedCurrentAuthorityDenialQuarantinesExactOwner(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1), imageID: "owned-image"}
	spec := statusTestSpec()
	denied := errors.New("current EC2 IAM denied")
	var reject atomic.Bool
	spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) {
		if reject.Load() {
			return msk.BrokerNetwork{}, denied
		}
		return spec.Networks[0], nil
	}
	var running atomic.Bool
	running.Store(true)
	var stopped atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.44")
		switch {
		case path == "/version":
			w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
		case path == "/info":
			w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		case path == "/containers/owned-broker/stop":
			running.Store(false)
			stopped.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
			state := containerState{ID: "owned-broker", Image: d.imageID}
			state.Config.Labels = d.labels(spec, "broker-1")
			state.State.Running = running.Load()
			json.NewEncoder(w).Encode(state)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d.client = client
	entered, release := make(chan struct{}), make(chan struct{})
	observe := func(ctx context.Context, current msk.Specification) (msk.Endpoint, error) {
		_, err := current.RefreshNetwork(ctx, 0)
		close(entered)
		<-release
		return msk.Endpoint{}, err
	}
	leader := make(chan error, 1)
	go func() { _, err := d.status(t.Context(), spec, observe); leader <- err }()
	awaitStatusJoin(t, entered)
	joined := &joinedStatusContext{Context: t.Context(), reached: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := d.status(joined, spec, observe); result <- err }()
	awaitStatusJoin(t, joined.reached)
	reject.Store(true)
	close(release)
	if err := awaitStatus(t, leader); err != nil {
		t.Fatal(err)
	}
	if err := awaitStatus(t, result); !errors.Is(err, denied) {
		t.Fatalf("current authority failure promoted old readiness: %v", err)
	}
	if running.Load() || stopped.Load() != 1 {
		t.Fatal("denied caller did not quarantine exact owned broker")
	}
}

func TestNextStatusNeverCachesMissingPolicyOrRestartedMarker(t *testing.T) {
	for _, name := range []string{"external-policy-loss", "same-container-restart"} {
		t.Run(name, func(t *testing.T) {
			d := &Docker{gate: make(chan struct{}, 1)}
			spec := statusTestSpec()
			spec.RefreshNetwork = func(context.Context, int) (msk.BrokerNetwork, error) { return spec.Networks[0], nil }
			missing := errors.New(name)
			var proofs int
			observe := func(context.Context, msk.Specification) (msk.Endpoint, error) {
				proofs++
				if proofs == 2 {
					return msk.Endpoint{}, missing
				}
				return msk.Endpoint{}, nil
			}
			if _, err := d.status(t.Context(), spec, observe); err != nil {
				t.Fatal(err)
			}
			if _, err := d.status(t.Context(), spec, observe); !errors.Is(err, missing) {
				t.Fatalf("completed flight hid physical loss: %v", err)
			}
			if proofs != 2 {
				t.Fatalf("physical observations=%d", proofs)
			}
		})
	}
}

func TestStatusGateWaitingRemainsCallerCancellable(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1)}
	d.gate <- struct{}{}
	defer d.unlock()
	spec := statusTestSpec()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := d.statusOnce(ctx, spec); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked gate ignored caller cancellation: %v", err)
	}
}

func TestObservedNetworkSnapshotOwnsPolicyAndRecursiveDNSInputs(t *testing.T) {
	original := statusTestSpec().Networks[0].Network
	original.Policy.SecurityIngress = []network.IPRule{{Protocol: 6, FromPort: 9096, ToPort: 9096}}
	original.ServiceEndpoints = []network.ServiceEndpoint{{ID: "vpce-owned", Network: network.Specification{DNS: []netip.Addr{netip.MustParseAddr("10.4.0.2")}}}}
	snapshot := cloneObservedNetwork(original)
	original.DNS[0] = netip.MustParseAddr("fd00::53")
	original.Policy.SecurityIngress[0].FromPort = 0
	original.ServiceEndpoints[0].Network.DNS[0] = netip.MustParseAddr("fd00::54")
	if equalObservedNetwork(original, snapshot) || snapshot.DNS[0].Is6() || snapshot.Policy.SecurityIngress[0].FromPort != 9096 || snapshot.ServiceEndpoints[0].Network.DNS[0].Is6() {
		t.Fatal("fresh owner backing slices rewrote an earlier flight proof")
	}
}

func TestStatusIntentFencesImmutableOwnerCredentialsAndPlacement(t *testing.T) {
	original := statusTestSpec()
	cases := map[string]func(*msk.Specification){
		"arn":           func(s *msk.Specification) { s.ARN += "foreign" },
		"incarnation":   func(s *msk.Specification) { s.Incarnation = "replacement" },
		"account":       func(s *msk.Specification) { s.AccountID = "222222222222" },
		"region":        func(s *msk.Specification) { s.Region = "us-west-2" },
		"configuration": func(s *msk.Specification) { s.ServerProperties = "auto.create.topics.enable=false" },
		"secret":        func(s *msk.Specification) { s.Users[0].Password = "replacement" },
		"interface":     func(s *msk.Specification) { s.Networks[0].InterfaceID = "eni-foreign" },
		"subnet":        func(s *msk.Specification) { s.Networks[0].SubnetID = "subnet-foreign" },
		"address":       func(s *msk.Specification) { s.Networks[0].Network.Address = netip.MustParseAddr("10.4.0.5") },
		"mac":           func(s *msk.Specification) { s.Networks[0].Network.MAC = "02:00:00:00:00:05" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			different := original
			different.Users = append([]msk.SCRAMUser(nil), original.Users...)
			different.Networks = append([]msk.BrokerNetwork(nil), original.Networks...)
			change(&different)
			if sameStatusIntent(original, different) {
				t.Fatal("different owner/runtime intent joined another proof")
			}
		})
	}
}

func TestFailedLeaderNeverPromotesEndpoint(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1)}
	spec := statusTestSpec()
	failure := errors.New("physical policy proof failed")
	entered, release := make(chan struct{}), make(chan struct{})
	observe := func(context.Context, msk.Specification) (msk.Endpoint, error) {
		close(entered)
		<-release
		return msk.Endpoint{}, failure
	}
	leader := make(chan error, 1)
	go func() { _, err := d.status(t.Context(), spec, observe); leader <- err }()
	awaitStatusJoin(t, entered)
	joined := &joinedStatusContext{Context: t.Context(), reached: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, err := d.status(joined, spec, observe); result <- err }()
	awaitStatusJoin(t, joined.reached)
	close(release)
	if err := awaitStatus(t, leader); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := awaitStatus(t, result); !errors.Is(err, failure) {
		t.Fatal("failed leader became successful readiness", err)
	}
}

func TestStatusReadsExactBrokerWithoutCreatingHelperAndQuarantinesFailedProof(t *testing.T) {
	d := &Docker{gate: make(chan struct{}, 1), imageID: "owned-image"}
	spec := statusTestSpec()
	var running atomic.Bool
	running.Store(true)
	var archives, created, stopped atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.44")
		switch {
		case path == "/version":
			w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
		case path == "/info":
			w.Write([]byte(`{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		case strings.HasPrefix(path, "/volumes/"):
			json.NewEncoder(w).Encode(volumeState{Name: resourceName(spec, "config"), Driver: "local", Labels: d.labels(spec, "config")})
		case path == "/containers/create":
			created.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		case path == "/containers/owned-broker/archive":
			archives.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"message":"retained material unavailable"}`))
		case path == "/containers/owned-broker/stop":
			running.Store(false)
			stopped.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
			config := d.containerConfig(spec, "broker-1", nil)
			json.NewEncoder(w).Encode(map[string]any{"Id": "owned-broker", "Image": d.imageID, "Config": config, "HostConfig": config.HostConfig, "State": map[string]any{"Running": running.Load()}, "NetworkSettings": map[string]any{"Networks": map[string]any{resourceName(spec, "network"): map[string]any{"Aliases": []string{resourceName(spec, "internal-1")}, "GwPriority": 100}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d.client = client
	if _, err := d.Status(t.Context(), spec); err == nil || !strings.Contains(err.Error(), "retained material unavailable") {
		t.Fatalf("failed physical proof became ready: %v", err)
	}
	if archives.Load() != 1 || created.Load() != 0 || stopped.Load() != 1 || running.Load() {
		t.Fatalf("archives=%d helpers=%d stops=%d running=%t", archives.Load(), created.Load(), stopped.Load(), running.Load())
	}
}
