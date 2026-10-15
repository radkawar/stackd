package valkey

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
)

type managedDaemonFixture struct {
	mu         sync.Mutex
	nodes      map[string]containerState
	volumes    map[string]volumeState
	manifest   manifest
	calls      []string
	failPolicy bool
}

func managedFixture(t *testing.T) (*Docker, Specification, *managedDaemonFixture) {
	t.Helper()
	d := &Docker{namespace: "test", image: "installed-valkey", toolkitImage: "installed-toolkit", gate: make(chan struct{}, 1), startupTimeout: time.Second}
	spec := managedTestSpec()
	spec.TLSEnabled = false
	f := &managedDaemonFixture{nodes: map[string]containerState{}, volumes: map[string]volumeState{}, manifest: managedManifest(spec)}
	for _, role := range []string{"ownership", "data"} {
		f.volumes[d.name(spec.ID, role)] = volumeState{Name: d.name(spec.ID, role), Driver: "local", Labels: d.managedLabels(spec, role)}
	}
	for _, role := range []string{"configuration", "node-1", "node-2"} {
		f.nodes[d.name(spec.ID, role)] = managedTestState(t, d, spec, role)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/v1.44")
		f.calls = append(f.calls, r.Method+" "+path)
		switch {
		case path == "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
		case path == "/info":
			if f.failPolicy {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"authoritative native policy installer failed"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ID":"test-engine","OSType":"linux","MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
		case path == "/containers/json":
			var filters map[string][]string
			if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
				t.Error(err)
			}
			for key, value := range d.managedLabels(spec, "copy-helper") {
				if key != labelPrefix+"role" && !strings.Contains(strings.Join(filters["label"], "\n"), key+"="+value) {
					t.Errorf("discovery omitted owner %s", key)
				}
			}
			_, _ = w.Write([]byte(`[]`))
		case strings.HasPrefix(path, "/volumes/"):
			name := strings.TrimPrefix(path, "/volumes/")
			v, exists := f.volumes[name]
			if exists && r.Method == http.MethodDelete {
				delete(f.volumes, name)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if exists {
				_ = json.NewEncoder(w).Encode(v)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"absent"}`))
		case strings.HasPrefix(path, "/containers/"):
			part := strings.TrimPrefix(path, "/containers/")
			name, action, _ := strings.Cut(part, "/")
			var state containerState
			var key string
			for candidate, s := range f.nodes {
				if candidate == name || s.ID == name {
					state, key = s, candidate
					break
				}
			}
			if key == "" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"absent"}`))
				return
			}
			switch {
			case action == "json":
				_ = json.NewEncoder(w).Encode(state)
			case action == "stop":
				state.State.Running = false
				state.State.Status = "exited"
				f.nodes[key] = state
				w.WriteHeader(http.StatusNoContent)
			case action == "archive" && r.Method == http.MethodGet:
				body, err := json.Marshal(f.manifest)
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/x-tar")
				tarWriter := tar.NewWriter(w)
				if err := tarWriter.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(body))}); err != nil {
					t.Error(err)
				}
				if _, err := tarWriter.Write(body); err != nil {
					t.Error(err)
				}
				if err := tarWriter.Close(); err != nil {
					t.Error(err)
				}
			case action == "archive" && r.Method == http.MethodPut:
				w.WriteHeader(http.StatusNoContent)
			case action == "" && r.Method == http.MethodDelete:
				delete(f.nodes, key)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"absent"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"absent"}`))
		}
	}))
	t.Cleanup(server.Close)
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	d.client = client
	bridges, err := network.NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	d.networks = bridges
	return d, spec, f
}
func (f *managedDaemonFixture) assertStoppedAndRetained(t *testing.T, d *Docker, spec Specification) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.nodes {
		if s.Config.Labels[labelPrefix+"role"] != "configuration" && s.State.Running {
			t.Fatal("failed observation left an exact-owned listener running")
		}
	}
	if len(f.volumes) != 2 || f.volumes[d.name(spec.ID, "data")].Name == "" || f.volumes[d.name(spec.ID, "ownership")].Name == "" {
		t.Fatal("quarantine deleted retained data/ownership")
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Fatalf("quarantine destroyed native recovery ownership: %s", call)
		}
	}
}

func TestManagedQuarantineNeedsNoNetworkObservationAndIgnoresCancellation(t *testing.T) {
	d, spec, f := managedFixture(t)
	spec.Networks = nil
	spec.RefreshNetwork = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := d.Quarantine(ctx, spec); err != nil {
		t.Fatal(err)
	}
	f.assertStoppedAndRetained(t, d, spec)
}
func TestManagedQuarantineNeverStopsCrossScopeOrNewIncarnation(t *testing.T) {
	for _, test := range []struct{ name, label, value string }{
		{"foreign-account", "account", "222222222222"},
		{"foreign-region", "region", "us-west-2"},
		{"replacement", "id", "new-incarnation"},
		{"foreign-node", "role", "node-2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, spec, f := managedFixture(t)
			f.mu.Lock()
			state := f.nodes[d.name(spec.ID, "node-1")]
			state.Config.Labels[labelPrefix+test.label] = test.value
			f.nodes[d.name(spec.ID, "node-1")] = state
			f.mu.Unlock()
			spec.Networks = nil
			if err := d.Quarantine(t.Context(), spec); err == nil {
				t.Fatal("ambiguous owner reported quarantine success")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !f.nodes[d.name(spec.ID, "node-1")].State.Running {
				t.Fatal("quarantine stopped foreign/replaced native process")
			}
			if f.nodes[d.name(spec.ID, "node-2")].State.Running {
				t.Fatal("quarantine failed to stop independent exact-owned node")
			}
		})
	}
}
func TestManagedFailedCurrentObservationQuarantinesUnderRuntimeLock(t *testing.T) {
	d, spec, f := managedFixture(t)
	called := false
	failure := errors.New("current EC2 observation denied")
	spec.RefreshNetwork = func(ctx context.Context, index int) (NodeNetwork, error) {
		if index != 0 || len(d.gate) != 1 {
			t.Error("refresh was not zero-indexed under native runtime installation lock")
		}
		called = true
		return NodeNetwork{}, failure
	}
	deployment, err := d.Ensure(t.Context(), spec)
	if !errors.Is(err, failure) || !called || len(deployment.Nodes) != 0 {
		t.Fatalf("failed authoritative observation exposed ready deployment: %+v %v", deployment, err)
	}
	f.assertStoppedAndRetained(t, d, spec)
}

func TestManagedStartupRequiresCurrentNetworkPolicy(t *testing.T) {
	for _, missing := range []string{"observation", "bridge-manager"} {
		t.Run(missing, func(t *testing.T) {
			driver, spec, daemon := managedFixture(t)
			if missing == "observation" {
				spec.RefreshNetwork = nil
			} else {
				driver.networks = nil
				spec.RefreshNetwork = func(_ context.Context, index int) (NodeNetwork, error) { return spec.Networks[index], nil }
			}
			out, err := driver.Ensure(t.Context(), spec)
			if err == nil || len(out.Nodes) != 0 {
				t.Fatalf("missing network authority admitted native listener: %+v %v", out, err)
			}
			daemon.assertStoppedAndRetained(t, driver, spec)
			daemon.mu.Lock()
			defer daemon.mu.Unlock()
			for _, call := range daemon.calls {
				if strings.HasSuffix(call, "/start") || strings.Contains(call, "/exec") || strings.Contains(call, "/archive") {
					t.Fatalf("missing authority reached startup or protocol admission: %s", call)
				}
			}
		})
	}
}
func TestManagedChangedObservationIdentityQuarantinesWithoutInstalling(t *testing.T) {
	d, spec, f := managedFixture(t)
	spec.RefreshNetwork = func(ctx context.Context, index int) (NodeNetwork, error) {
		changed := spec.Networks[index]
		changed.InterfaceID = "foreign-eni"
		return changed, nil
	}
	if _, err := d.Ensure(t.Context(), spec); err == nil {
		t.Fatal("changed immutable EC2 identity was admitted")
	}
	f.assertStoppedAndRetained(t, d, spec)
}
func TestManagedIDOnlyDeleteRetainsDescriptorAcrossNativePolicyFailure(t *testing.T) {
	d, spec, f := managedFixture(t)
	// No Specification or EC2 callback is supplied to Delete. Its own retained
	// immutable descriptor must carry the policy/bridge owner after data removal.
	f.mu.Lock()
	f.failPolicy = true
	f.mu.Unlock()
	if err := d.Delete(t.Context(), spec.ID); err == nil || !strings.Contains(err.Error(), "authoritative native policy installer failed") {
		t.Fatalf("Delete did not reach exact owned native policy retirement: %v", err)
	}
	f.mu.Lock()
	if len(f.nodes) != 0 || f.volumes[d.name(spec.ID, "data")].Name != "" {
		f.mu.Unlock()
		t.Fatal("Delete did not remove exact-owned listeners/data before retiring policy")
	}
	if f.volumes[d.name(spec.ID, "ownership")].Name == "" {
		f.mu.Unlock()
		t.Fatal("Delete lost durable policy cleanup ownership")
	}
	f.mu.Unlock()
	owner, found, err := d.managedDescriptor(t.Context(), spec.ID)
	if err != nil || !found || len(owner.Networks) != 2 || owner.Networks[0] != attachment(spec, 0) || owner.Networks[1] != attachment(spec, 1) {
		t.Fatalf("reopened deletion cannot recover exact owned native policy: %+v %t %v", owner, found, err)
	}
	if err := d.Delete(t.Context(), spec.ID); err == nil || !strings.Contains(err.Error(), "authoritative native policy installer failed") {
		t.Fatalf("retry forgot failed native policy retirement: %v", err)
	}
}
func TestManagedDeletePreflightsAllOwnersBeforeAnyDeletion(t *testing.T) {
	d, spec, f := managedFixture(t)
	f.mu.Lock()
	state := f.nodes[d.name(spec.ID, "node-2")]
	state.Config.Labels[labelPrefix+"arn"] = "arn:aws:elasticache:us-east-1:222222222222:replicationgroup:cache"
	f.nodes[d.name(spec.ID, "node-2")] = state
	f.mu.Unlock()
	if err := d.Delete(t.Context(), spec.ID); err == nil {
		t.Fatal("Delete accepted cross-scope native node")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Fatal("Delete mutated before complete immutable ownership preflight")
		}
	}
	if len(f.volumes) != 2 || len(f.nodes) != 3 {
		t.Fatal("foreign ownership failure removed unrelated native resources")
	}
}

func TestManagedPartialCreateRollsBackEvenWhenContainerNeverLanded(t *testing.T) {
	d, spec, f := managedFixture(t)
	f.mu.Lock()
	delete(f.nodes, d.name(spec.ID, "node-1"))
	f.failPolicy = true
	f.mu.Unlock()
	cause := errors.New("node create failed after bridge admission")
	if err := d.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	err := d.managedFailure(t.Context(), spec, []string{"node-1"}, cause)
	d.unlock()
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "authoritative native policy installer failed") {
		t.Fatalf("missing container skipped its exact policy/bridge rollback: %v", err)
	}
	f.assertStoppedAndRetained(t, d, spec)
}

func TestManagedNativeStartupGraceDoesNotHideLiveProtocolFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	m := manifest{Nodes: []nativeNode{{Address: "127.0.0.1", Port: int32(listener.Addr().(*net.TCPAddr).Port)}}}
	d := &Docker{}
	for _, started := range [][]bool{nil, {false}} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := d.checkManagedNative(ctx, m, started)
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("live protocol failure was hidden by startup grace: started=%v error=%v", started, err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := d.checkManagedNative(ctx, m, []bool{true}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("newly started node lost its startup/recovery grace: %v", err)
	}
}
