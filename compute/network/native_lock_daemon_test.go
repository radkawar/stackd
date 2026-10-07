package network

import (
	"context"
	"crypto/rand"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

func daemonNetworkTestEngine(t *testing.T) *docker.Client {
	t.Helper()
	if os.Getenv("STACKD_NETWORK_DOCKER") != "1" {
		t.Skip("set STACKD_NETWORK_DOCKER=1 for actual daemon-host network admission")
	}
	client, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestDaemonNativeBridgeAdmission(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	bridges, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	// Independent controller bridge owners must serialize on the daemon's lock,
	// not on either controller's process-local mutex or filesystem namespace.
	successor, err := NewDaemonBridges(client)
	if err != nil {
		t.Fatal(err)
	}
	spec := Specification{NetworkID: "daemon-admission-" + rand.Text(), Pool: netip.MustParsePrefix("10.254.248.0/24"), Gateway: netip.MustParseAddr("10.254.248.1"), Address: netip.MustParseAddr("10.254.248.10")}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := bridges.Release(ctx, spec.NetworkID); err != nil {
			t.Error(err)
		}
	})
	type outcome struct {
		bridge Bridge
		err    error
	}
	results := make(chan outcome, 2)
	for _, owner := range []*Bridges{bridges, successor} {
		go func() {
			var result outcome
			result.err = owner.WithBridge(t.Context(), spec, func(bridge Bridge) error { result.bridge = bridge; return nil })
			results <- result
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("actual daemon admissions failed: %v / %v", first.err, second.err)
	}
	if first.bridge != second.bridge || first.bridge.Name == "" || first.bridge.Device == "" {
		t.Fatalf("controllers did not retain the same actual bridge: %+v %+v", first.bridge, second.bridge)
	}
}

func TestDaemonNativeLockRejectsWrongEngineSocket(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	// Use the real daemon socket but an intentionally wrong selected identity.
	// The real flock and /info observation must reject before the payload runs.
	output, err := docker.RunHelper(t.Context(), client, "network-wrong-engine", docker.ContainerConfig{
		Image: docker.ToolkitImage, Entrypoint: []string{"python3", "-c", nativeDaemonLockScript}, Cmd: []string{"printf forbidden-native-mutation"},
		Env: []string{"NATIVE_ENGINE_ID=not-the-selected-daemon"},
		HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Mounts: []docker.ContainerMount{{Type: "bind", Source: "/run/lock", Target: "/run/lock"}, {Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true}},
			Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32},
	})
	if err == nil || !strings.Contains(err.Error(), "native network helper socket does not identify the selected Linux Engine") || strings.Contains(string(output), "forbidden-native-mutation") || strings.Contains(err.Error(), "forbidden-native-mutation") {
		t.Fatalf("wrong Engine identity admitted native mutation: output=%q err=%v", output, err)
	}
}
