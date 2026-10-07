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
			Mounts: []docker.ContainerMount{{Type: "bind", Source: "/run", Target: "/stackd-host-run"}, {Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true}},
			Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32},
	})
	if err == nil || !strings.Contains(err.Error(), "native network helper socket does not identify the selected Linux Engine") || strings.Contains(string(output), "forbidden-native-mutation") || strings.Contains(err.Error(), "forbidden-native-mutation") {
		t.Fatalf("wrong Engine identity admitted native mutation: output=%q err=%v", output, err)
	}
}

func TestDaemonNativeLockCreatesMissingDirectoryAndRetainsExclusiveInode(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	var engine struct{ ID string }
	if err := client.JSON(t.Context(), "GET", "/info", nil, &engine); err != nil {
		t.Fatal(err)
	}
	// An empty daemon volume models a VM /run without /run/lock without
	// deleting or replacing the selected host's real shared lock directory.
	volume := "stackd-network-lock-fixture-" + rand.Text()
	if err := client.JSON(t.Context(), "POST", "/volumes/create", struct{ Name string }{volume}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.JSON(ctx, "DELETE", "/volumes/"+volume, nil, nil); err != nil {
			t.Error(err)
		}
	})
	config := docker.ContainerConfig{
		Image: docker.ToolkitImage,
		Env:   []string{"NATIVE_ENGINE_ID=" + engine.ID},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Mounts: []docker.ContainerMount{
				{Type: "volume", Source: volume, Target: "/stackd-host-run"},
				{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true},
			},
			Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
		},
	}
	config.Entrypoint = []string{"python3", "-c", nativeDaemonLockScript}
	config.Cmd = []string{`python3 -c '
import fcntl, os, stat
path = "/stackd-host-run/lock/stackd-public-network.lock"
held, current = os.fstat(9), os.stat(path, follow_symlinks=False)
assert stat.S_ISREG(current.st_mode)
assert (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)
fd = os.open(path, os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("same-inode-exclusive")
else:
    raise SystemExit("native mutation did not inherit an exclusive lock")
'`}
	output, err := docker.RunHelper(t.Context(), client, "network-missing-lock-directory", config)
	if err != nil || strings.TrimSpace(string(output)) != "same-inode-exclusive" {
		t.Fatalf("missing daemon lock directory was not safely admitted: output=%q err=%v", output, err)
	}
	// A successor must acquire the same inode after the admission exits.
	config.Entrypoint = []string{"python3", "-c", `
import fcntl, os
fd = os.open("/stackd-host-run/lock/stackd-public-network.lock", os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("successor-acquired")
`}
	config.Cmd = nil
	output, err = docker.RunHelper(t.Context(), client, "network-released-lock", config)
	if err != nil || strings.TrimSpace(string(output)) != "successor-acquired" {
		t.Fatalf("daemon admission leaked an exclusive lock: output=%q err=%v", output, err)
	}
}
