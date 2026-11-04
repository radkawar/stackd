package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"stackd/compute/docker"
)

func TestNativeNetworkLockRestrictiveUmask(t *testing.T) {
	const childPath = "STACKD_LOCK_UMASK_CHILD_PATH"
	if path := os.Getenv(childPath); path != "" {
		unix.Umask(0077)
		file, err := openNativeNetworkLock(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	client := daemonNetworkTestEngine(t)
	path := filepath.Join(t.TempDir(), "network.lock")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the process-wide umask change out of concurrent package tests.
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestNativeNetworkLockRestrictiveUmask$")
	command.Env = append(os.Environ(), childPath+"="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create restrictive-umask lock: %v: %s", err, output)
	}
	file, err := openNativeNetworkLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	config := docker.ContainerConfig{
		Image: docker.ToolkitImage, User: "65534:65534",
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Mounts:      []docker.ContainerMount{{Type: "bind", Source: path, Target: "/network.lock", ReadOnly: true}},
		},
		Entrypoint: []string{"python3", "-c", `
import fcntl, os
fd = os.open("/network.lock", os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("shared-exclusive-lock")
else:
    raise SystemExit("controller lock was not shared with the daemon helper")
`},
	}
	output, err := docker.RunHelper(t.Context(), client, "network-umask-lock", config)
	if err != nil || strings.TrimSpace(string(output)) != "shared-exclusive-lock" {
		t.Fatalf("cross-user helper could not observe the held lock: output=%q err=%v", output, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	config.Entrypoint = []string{"python3", "-c", `
import fcntl, os
fd = os.open("/network.lock", os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("successor-acquired")
`}
	output, err = docker.RunHelper(t.Context(), client, "network-umask-successor", config)
	if err != nil || strings.TrimSpace(string(output)) != "successor-acquired" {
		t.Fatalf("cross-user helper could not acquire the released lock: output=%q err=%v", output, err)
	}
}
