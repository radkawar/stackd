package network

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
)

//go:embed flows_receiver.py
var flowReceiverScript string

//go:embed flows_bootstrap.py
var flowBootstrapScript string

//go:embed flows_control.py
var flowControlScript string

// DockerFlowCollector adopts a retained namespace-owned receiver. No process or
// client-global registry is used: independent managers converge under the same
// daemon-host native network flock. The steady receiver has no Engine socket.
type DockerFlowCollector struct {
	client    *docker.Client
	namespace string
	name      string
	volume    string
	mu        sync.Mutex
	engineID  string
}

var _ NativeFlowCollector = (*DockerFlowCollector)(nil)

func NewDockerFlowCollector(client *docker.Client, namespace string) (*DockerFlowCollector, error) {
	if client == nil || namespace == "" || len(namespace) > 256 || strings.ContainsRune(namespace, '\x00') {
		return nil, errors.New("native flow collector requires a Docker client and nonempty bounded namespace")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(namespace)))
	return &DockerFlowCollector{client: client, namespace: namespace, name: "stackd-flows-" + digest, volume: "stackd-flows-" + digest}, nil
}

// Ensure performs daemon-side admission, verifies exact retained ownership and
// waits for a real NFNETLINK group bind. It does not touch packet policy.
func (c *DockerFlowCollector) Ensure(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensure(ctx, false, nil)
}

func (c *DockerFlowCollector) ensure(ctx context.Context, cleanup bool, reconcile *FlowReconcile) error {
	var engine struct {
		ID, OSType      string
		SecurityOptions []string
	}
	if err := c.client.JSON(ctx, "GET", "/info", nil, &engine); err != nil {
		return err
	}
	if engine.ID == "" || engine.OSType != "linux" {
		return errors.New("native flow capture requires an identified Linux Engine")
	}
	for _, option := range engine.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return errors.New("native flow capture requires rootful Docker without user namespace remapping")
		}
	}
	labels := map[string]string{"stackd.network.flows.namespace": c.namespace, "stackd.network.flows.engine": engine.ID, "stackd.network.flows.version": "1"}
	config := docker.ContainerConfig{
		Image:      docker.ToolkitImage,
		Entrypoint: []string{"python3", "-c", flowReceiverScript},
		Cmd:        []string{"--stackd-flow-receiver"}, User: "0:0",
		Env:    []string{"FLOW_NAMESPACE=" + c.namespace, "FLOW_ENGINE_ID=" + engine.ID, "PYTHONDONTWRITEBYTECODE=1"},
		Labels: labels,
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "host", ReadonlyRootfs: true,
			CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"},
			Mounts: []docker.ContainerMount{{Type: "volume", Source: c.volume, Target: "/flows", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}},
			Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: 32,
			LogConfig: docker.ContainerLogConfig{Type: "none", Config: map[string]string{}},
		},
	}
	body, err := json.Marshal(config)
	if err != nil {
		return err
	}
	// Bootstrap holds the existing daemon network lock only for inspection and
	// create/start. The receiver never retains this global mutation lock.
	bootstrap := docker.ContainerConfig{
		Image:      docker.ToolkitImage,
		Entrypoint: []string{"python3", "-c", nativeDaemonLockScript},
		Cmd:        []string{"exec python3 -c \"$FLOW_BOOTSTRAP\""},
		Env:        []string{"NATIVE_ENGINE_ID=" + engine.ID, "FLOW_BOOTSTRAP=" + flowBootstrapScript, "FLOW_CONFIG=" + base64.StdEncoding.EncodeToString(body), "FLOW_NAME=" + c.name, "FLOW_VOLUME=" + c.volume},
		Labels:     labels,
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Mounts: []docker.ContainerMount{{Type: "bind", Source: "/run", Target: "/stackd-host-run"}, {Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock", ReadOnly: true}},
			Memory: 96 << 20, MemorySwap: 96 << 20, PidsLimit: 16,
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	}
	if cleanup {
		bootstrap.Env = append(bootstrap.Env, "FLOW_CLEANUP=1")
	}
	if reconcile != nil {
		data, err := json.Marshal(reconcile)
		if err != nil {
			return err
		}
		bootstrap.Env = append(bootstrap.Env, "FLOW_RECONCILE="+base64.StdEncoding.EncodeToString(data))
	}
	output, err := docker.RunHelper(ctx, c.client, "flow-admission", bootstrap)
	if err != nil {
		return fmt.Errorf("admit retained native flow collector: %w", err)
	}
	if cleanup {
		c.engineID = ""
		return nil
	}
	var admitted struct {
		Marker string `json:"marker"`
		BootID string `json:"boot_id"`
	}
	if err := json.Unmarshal(output, &admitted); err != nil {
		return fmt.Errorf("decode daemon flow admission: %w", err)
	}
	if admitted.Marker != "STACKD_FLOW_COLLECTOR_ADMITTED" || admitted.BootID == "" {
		return errors.New("daemon flow admission omitted verified boot identity")
	}
	c.engineID = engine.ID
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		var health FlowHealth
		last = c.control(ctx, map[string]any{"op": "health"}, &health)
		if last == nil && health.Ready && health.EngineID == engine.ID && health.BootID == admitted.BootID && health.Group != 0 {
			return nil
		}
		if last == nil {
			last = errors.New("receiver readiness identity mismatch")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("native NFLOG receiver not ready: %w", last)
		case <-ticker.C:
		}
	}
}

func (c *DockerFlowCollector) control(ctx context.Context, input any, output any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	containerID, err := c.ownedContainer(ctx)
	if err != nil {
		return err
	}
	request, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(request) > 64<<10 {
		return errors.New("native flow control request exceeds 64 KiB")
	}
	var created struct {
		ID string `json:"Id"`
	}
	config := map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": []string{"python3", "-c", flowControlScript, base64.StdEncoding.EncodeToString(request)}}
	if err := c.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(containerID)+"/exec", config, &created); err != nil {
		return err
	}
	response, err := c.client.Request(ctx, "POST", "/exec/"+url.PathEscape(created.ID)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var stdout, stderr bytes.Buffer
	limited := &io.LimitedReader{R: response.Body, N: (2 << 20) + 1}
	if err := docker.CopyStream(&stdout, &stderr, limited); err != nil {
		return err
	}
	if limited.N == 0 {
		return errors.New("native flow control response exceeds 2 MiB")
	}
	var status struct {
		Running  bool
		ExitCode int
	}
	if err := c.client.JSON(ctx, "GET", "/exec/"+url.PathEscape(created.ID)+"/json", nil, &status); err != nil {
		return err
	}
	if status.Running || status.ExitCode != 0 {
		return fmt.Errorf("native flow control failed (exit %d): %s", status.ExitCode, stderr.String())
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		return fmt.Errorf("decode native flow control: %w", err)
	}
	if envelope.Error != "" {
		return errors.New(envelope.Error)
	}
	if output != nil {
		return json.Unmarshal(envelope.Result, output)
	}
	return nil
}

// Resolve to an immutable container ID before exec/archive so a concurrent name
// replacement cannot redirect control or reveal an unrelated filesystem.
func (c *DockerFlowCollector) ownedContainer(ctx context.Context) (string, error) {
	var info struct {
		ID     string `json:"Id"`
		Config struct {
			Image, User          string
			Entrypoint, Cmd, Env []string
			Labels               map[string]string
		}
		HostConfig struct {
			NetworkMode                string
			ReadonlyRootfs, Privileged bool
			CapAdd, CapDrop            []string
		}
		Mounts []struct {
			Type, Name, Destination string
			RW                      bool
		}
	}
	if err := c.client.JSON(ctx, "GET", "/containers/"+url.PathEscape(c.name)+"/json", nil, &info); err != nil {
		return "", err
	}
	labels := info.Config.Labels
	if info.ID == "" || labels["stackd.network.flows.namespace"] != c.namespace || labels["stackd.network.flows.engine"] != c.engineID || labels["stackd.network.flows.version"] != "1" ||
		info.Config.Image != docker.ToolkitImage || info.Config.User != "0:0" || !slices.Equal(info.Config.Entrypoint, []string{"python3", "-c", flowReceiverScript}) || !slices.Equal(info.Config.Cmd, []string{"--stackd-flow-receiver"}) ||
		info.HostConfig.NetworkMode != "host" || !info.HostConfig.ReadonlyRootfs || info.HostConfig.Privileged || !slices.Equal(info.HostConfig.CapAdd, []string{"NET_ADMIN"}) || !slices.Equal(info.HostConfig.CapDrop, []string{"ALL"}) ||
		len(info.Mounts) != 1 || info.Mounts[0].Type != "volume" || info.Mounts[0].Name != c.volume || info.Mounts[0].Destination != "/flows" || !info.Mounts[0].RW {
		return "", errors.New("native flow collector ownership changed")
	}
	return info.ID, nil
}

func (c *DockerFlowCollector) call(ctx context.Context, input any, output any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var engine struct{ ID string }
	if err := c.client.JSON(ctx, "GET", "/info", nil, &engine); err != nil {
		return err
	}
	if engine.ID != c.engineID {
		c.engineID = ""
	}
	if c.engineID == "" {
		if err := c.ensure(ctx, false, nil); err != nil {
			return err
		}
	}
	if err := c.control(ctx, input, output); err != nil {
		// Do not automatically replay a possibly committed mutating operation.
		// The next explicit call re-admits/restarts the retained receiver.
		c.engineID = ""
		return err
	}
	return nil
}

func (c *DockerFlowCollector) Register(ctx context.Context, binding FlowBinding) (FlowRegistration, error) {
	var registration FlowRegistration
	if err := binding.Identity.Validate(binding.NetworkID); err != nil {
		return registration, err
	}
	// Engine-owned network labels, not a controller pathname or packet address,
	// prove that the requested bridge belongs to the full scoped VPC ARN.
	var network bridgeInfo
	if err := c.client.JSON(ctx, "GET", "/networks/"+url.PathEscape(bridgeName(binding.NetworkID)), nil, &network); err != nil {
		return registration, err
	}
	if network.Driver != "bridge" || network.Labels[BridgeLabel] != binding.NetworkID || len(network.ID) < 12 || network.device() != binding.Bridge {
		return registration, errors.New("flow registration bridge is not owned by the full VPC identity")
	}
	err := c.call(ctx, map[string]any{"op": "register", "binding": binding}, &registration)
	return registration, err
}

func (c *DockerFlowCollector) Retire(ctx context.Context, registration FlowRegistration) error {
	return c.call(ctx, map[string]any{"op": "retire", "registration": registration}, nil)
}

func (c *DockerFlowCollector) Read(ctx context.Context, after uint64, limits FlowReadLimits) (FlowBatch, error) {
	var batch FlowBatch
	err := c.call(ctx, map[string]any{"op": "read", "cursor": after, "limits": limits}, &batch)
	return batch, err
}

func (c *DockerFlowCollector) Ack(ctx context.Context, through uint64) error {
	return c.call(ctx, map[string]any{"op": "ack", "cursor": through}, nil)
}

func (c *DockerFlowCollector) Health(ctx context.Context) (FlowHealth, error) {
	var health FlowHealth
	err := c.call(ctx, map[string]any{"op": "health"}, &health)
	return health, err
}

func (c *DockerFlowCollector) Gap(ctx context.Context, gap FlowGap) error {
	return c.call(ctx, map[string]any{"op": "gap", "gap": gap}, nil)
}

// Archive returns only the private metadata/header-only journal through Engine's
// native archive endpoint. Caller must close the returned stream. It never
// accesses the controller's filesystem or stops/drains customer workloads.
func (c *DockerFlowCollector) Archive(ctx context.Context) (io.ReadCloser, error) {
	if _, err := c.Health(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	containerID, err := c.ownedContainer(ctx)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Request(ctx, "GET", "/containers/"+url.PathEscape(containerID)+"/archive?path="+url.QueryEscape("/flows"), nil, "")
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

func (c *DockerFlowCollector) Close() error { return nil }

// CleanupIdle removes only this exact-owned namespace after the live receiver
// atomically refuses further registrations and proves all bindings retired and
// every durable record acknowledged. Active or unread evidence is never killed.
func (c *DockerFlowCollector) CleanupIdle(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensure(ctx, true, nil)
}

func (c *DockerFlowCollector) Reconcile(ctx context.Context, reconciliation FlowReconcile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensure(ctx, false, &reconciliation)
}
