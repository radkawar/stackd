package eks

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The existing opt-in workload fixture calls this only after authenticated exec
// succeeds. Killing the daemon, rather than Docker's init process, catches the
// upstream entrypoint's otherwise invisible dead-child/uncordon loop.
func assertNativeWorkerDaemonRecovery(t *testing.T, ctx context.Context, runtime *K3d, id string, kubectlArgs []string) {
	t.Helper()
	state, err := readState(runtime.resourceDir(id), id)
	if err != nil {
		t.Fatal(err)
	}
	containers, err := runtime.ownedContainers(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	var worker *dockerContainer
	for i := range containers {
		if containers[i].Name == "/k3d-"+state.Name+"-agent-0" {
			worker = &containers[i]
			break
		}
	}
	if worker == nil {
		t.Fatal("exact-owned native worker is missing")
	}
	mounted := false
	for _, mount := range worker.Mounts {
		if mount.Destination == "/bin/k3d-entrypoint.sh" {
			mounted = mount.Type == "bind" && !mount.RW && mount.Source == filepath.Join(runtime.resourceDir(id), "control-plane-entrypoint.sh")
		}
	}
	if !mounted {
		t.Fatal("worker does not execute the owned read-only node entrypoint")
	}
	type nodeStatus struct {
		Metadata struct{ UID string }
		Status   struct {
			Conditions []struct{ Type, Status string }
		}
	}
	nodePath := "/api/v1/nodes/" + strings.TrimPrefix(worker.Name, "/")
	var original nodeStatus
	if code, err := runtime.clusters[id].workerRequest(ctx, "GET", nodePath, nil, &original); err != nil || code != 200 || original.Metadata.UID == "" {
		t.Fatalf("read original worker Node: HTTP %d: %v", code, err)
	}
	restarts := func(ctx context.Context) int {
		t.Helper()
		output, err := runtime.command(ctx, "docker", "container", "inspect", "--format", "{{.RestartCount}}", worker.ID)
		if err != nil {
			t.Fatalf("inspect exact worker restart count: %v", err)
		}
		count, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil {
			t.Fatalf("worker restart count: %v", err)
		}
		return count
	}
	before := restarts(ctx)
	// Only the actual agent directly parented by Docker's init is a target;
	// similarly named processes in workload PID namespaces confer no authority.
	killAgent := `read children </proc/1/task/1/children || test -n "$children"
for child in $children; do
  read name <"/proc/$child/comm"
  if [ "$name" = k3s ]; then
    kill -TERM "$child"
    exit 0
  fi
done
exit 1`
	if output, err := runtime.command(ctx, "docker", "exec", worker.ID, "/bin/sh", "-ec", killAgent); err != nil {
		t.Fatalf("terminate exact worker daemon: %v %s", err, output)
	}
	recovery, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for restarts(recovery) <= before {
		select {
		case <-recovery.Done():
			t.Fatal("worker daemon death did not restart the same Docker container:", recovery.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	var lastErr error
	var lastOutput []byte
	for {
		attempt, done := context.WithTimeout(recovery, 10*time.Second)
		lastOutput, lastErr = exec.CommandContext(attempt, "kubectl", kubectlArgs...).CombinedOutput()
		done()
		if lastErr == nil && strings.Contains(string(lastOutput), "exec-through-authenticated-proxy") {
			var node nodeStatus
			code, err := runtime.clusters[id].workerRequest(recovery, "GET", nodePath, nil, &node)
			if err == nil && code == 200 && node.Metadata.UID == original.Metadata.UID {
				for _, condition := range node.Status.Conditions {
					if condition.Type == "Ready" && condition.Status == "True" {
						t.Log("k3s agent death restarted the same exact-owned worker, preserved its Node UID, and restored real authenticated exec")
						return
					}
				}
			}
			lastErr = err
		}
		select {
		case <-recovery.Done():
			t.Fatalf("same worker did not restore Node Ready and real authenticated kubelet exec: %v %s", lastErr, lastOutput)
		case <-time.After(time.Second):
		}
	}
}
