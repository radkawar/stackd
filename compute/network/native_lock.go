package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"stackd/compute/docker"
)

// runNativeOperation observes an auto-removed daemon-side operation. Unlike an
// ordinary RunHelper, cancellation must not kill a holder of the network lock:
// an accepted Engine request can outlive its HTTP client. The helper completes
// the mutation and releases flock even if this controller dies or disconnects.
func (b *Bridges) runNativeOperation(ctx context.Context, owner string, environment []string, bridge bool) (output []byte, err error) {
	kind, script := "public-network", nativePolicyScript
	labels := map[string]string{"stackd.network.policy": owner}
	if bridge {
		kind, script = "network-admission", nativeBridgeScript
		labels = map[string]string{BridgeLabel: owner}
	}
	if strings.HasPrefix(owner, "stackd_eks_workers_") {
		kind, script = "eks-worker-peers", eksWorkerPeersScript
		labels = map[string]string{"stackd.eks.worker-peers": owner}
	}
	var engine struct {
		ID, OSType      string
		SecurityOptions []string
	}
	if err := b.client.JSON(ctx, "GET", "/info", nil, &engine); err != nil {
		return nil, fmt.Errorf("inspect native network host: %w", err)
	}
	if engine.OSType != "linux" || engine.ID == "" {
		return nil, errors.New("native public/private network admission requires an identified Linux Docker engine")
	}
	for _, option := range engine.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return nil, errors.New("native public/private network admission requires rootful Docker without user namespace remapping")
		}
	}
	identity := ""
	if !b.daemonOwned {
		identity, err = nativeNetworkIdentity(ctx)
		if err != nil {
			return nil, err
		}
	}
	const completed = "\nSTACKD_NATIVE_OPERATION_COMPLETE\n"
	const ready = "STACKD_NATIVE_OPERATION_READY\n"
	admissionScript := "\nprintf 'STACKD_NATIVE_OPERATION_READY\\n'\nIFS= read -r admission\n[ \"$admission\" = admit ]\n" + script + "\nprintf '\\nSTACKD_NATIVE_OPERATION_COMPLETE\\n'\n"
	entrypoint := []string{"/bin/sh", "-ec", nativeLockCheckScript + admissionScript}
	var command []string
	if b.daemonOwned {
		entrypoint = []string{"python3", "-c", nativeDaemonLockScript}
		command = []string{admissionScript}
	}
	config := docker.ContainerConfig{
		Image: docker.ToolkitImage, OpenStdin: true, StdinOnce: true,
		Entrypoint: entrypoint, Cmd: command,
		Env: append(environment, "NATIVE_LOCK_IDENTITY="+identity, "NATIVE_ENGINE_ID="+engine.ID), Labels: labels,
		HostConfig: docker.ContainerHostConfig{
			AutoRemove: true, NetworkMode: "host", ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Mounts:      []docker.ContainerMount{{Type: "bind", Source: "/run/lock", Target: "/run/lock", ReadOnly: !b.daemonOwned}},
			Memory:      64 << 20, MemorySwap: 64 << 20, PidsLimit: 32,
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	}
	if b.daemonOwned || bridge || strings.HasPrefix(owner, "stackd_eks_workers_") {
		config.HostConfig.Mounts = append(config.HostConfig.Mounts, docker.ContainerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true})
	}
	name := "stackd-" + kind + "-" + rand.Text()
	admitted := false
	defer func() {
		if !admitted {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if cleanupErr := b.client.RemoveContainer(cleanup, name); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove unadmitted native %s operation: %w", kind, cleanupErr))
			}
		}
	}()
	if err := b.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, nil); err != nil {
		return nil, fmt.Errorf("create native %s operation: %w", kind, err)
	}
	path := "/containers/" + url.PathEscape(name)
	// The duplex stream is established before start. EOF before the lock-held
	// admission handshake aborts an orphan waiter; admitted operations continue.
	response, err := b.client.RequestHeaders(ctx, "POST", path+"/attach?stream=true&stdin=true&stdout=true&stderr=true", nil, "", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"tcp"}})
	if err != nil {
		return nil, fmt.Errorf("observe native %s operation: %w", kind, err)
	}
	defer response.Body.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = response.Body.Close() })
	defer stopClose()
	input, ok := response.Body.(io.Writer)
	if !ok {
		return nil, errors.New("docker native admission requires a duplex attach stream")
	}
	if err := b.client.JSON(ctx, "POST", path+"/start", nil, nil); err != nil {
		return nil, fmt.Errorf("start native %s operation (completion may continue in daemon): %w", kind, err)
	}
	var stdout, stderr bytes.Buffer
	bounded := &io.LimitedReader{R: response.Body, N: (64 << 10) + 1}
	var buffer [4096]byte
	if err := docker.VisitStream(bounded, func(isStderr bool, frame io.Reader) error {
		destination := &stdout
		if isStderr {
			destination = &stderr
		}
		if _, err := io.CopyBuffer(destination, frame, buffer[:]); err != nil {
			return err
		}
		if !admitted && stdout.String() == ready {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Mark before writing: a partial transport failure can still deliver
			// admission. Never kill a possibly admitted Engine operation.
			admitted = true
			if _, err := io.WriteString(input, "admit\n"); err != nil {
				return err
			}
			stdout.Reset()
		}
		return nil
	}); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("observe native %s completion (operation continues in daemon): %w", kind, err)
	}
	if bounded.N == 0 {
		return nil, fmt.Errorf("native %s output exceeds 64 KiB", kind)
	}
	if !bytes.HasSuffix(stdout.Bytes(), []byte(completed)) {
		return nil, fmt.Errorf("native %s operation failed: stdout %q, stderr %q", kind, stdout.String(), stderr.String())
	}
	return stdout.Bytes()[:stdout.Len()-len(completed)], nil
}
