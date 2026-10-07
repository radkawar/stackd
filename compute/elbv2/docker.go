package elbv2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
)

const (
	ownerLabel        = "stackd.elbv2.load-balancer"
	attachmentLabel   = "stackd.elbv2.attachment"
	identityLabel     = "stackd.elbv2.identity"
	callbackHostLabel = "stackd.elbv2.callback.host"
	callbackPortLabel = "stackd.elbv2.callback.port"
	addressLabel      = "stackd.elbv2.address"
	networkLabel      = "stackd.elbv2.network"
	macLabel          = "stackd.elbv2.mac"
	executableLabel   = "stackd.elbv2.executable"
	relayExecutable   = "/stackd-elbv2-node"
)

// DockerConfig requires an explicitly installed static Linux relay executable
// and toolkit image. The adapter never downloads or builds either prerequisite.
type DockerConfig struct {
	Client     *docker.Client
	Networks   *network.Bridges
	Executable string
}

// Docker uses native sockets on a local rootful Linux Engine's VPC bridge.
// The caller owns Client and Networks and must keep them alive until detachment.
type Docker struct {
	client     *docker.Client
	networks   *network.Bridges
	executable string
	mu         sync.Mutex
	nodes      map[string]*dockerNode
}

func NewDocker(config DockerConfig) (*Docker, error) {
	if config.Client == nil || config.Networks == nil || config.Executable == "" {
		return nil, errors.New("ALB native runtime requires Docker, shared bridges and an explicit static relay executable")
	}
	executable, err := filepath.Abs(config.Executable)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(executable)
	if err != nil {
		return nil, fmt.Errorf("inspect ALB relay executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("ALB relay executable must be an executable regular file")
	}
	binary, err := elf.Open(executable)
	if err != nil {
		return nil, fmt.Errorf("ALB relay must be a static Linux ELF executable: %w", err)
	}
	defer binary.Close()
	if binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN {
		return nil, errors.New("ALB relay ELF is not executable")
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, errors.New("ALB relay must be statically linked; dynamic ELF interpreter found")
		}
	}
	return &Docker{client: config.Client, networks: config.Networks, executable: executable, nodes: make(map[string]*dockerNode)}, nil
}

type dockerNode struct {
	driver             *Docker
	spec               Specification
	bridge             network.Bridge
	id, identity, peer string
	callbackAddress    string
	callback           *callback
	policyMu           sync.Mutex
	policy             network.Policy
}

type nodeInspection struct {
	ID     string `json:"Id"`
	Config struct {
		Labels          map[string]string
		Image           string
		Entrypoint, Cmd []string
	}
	State struct {
		Running, Paused, Restarting, Dead bool
		Status                            string
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress, Gateway, MacAddress string }
	}
}

func resourceKey(spec Specification) string { return spec.LoadBalancerARN + "\x00" + spec.AttachmentID }
func containerName(spec Specification) string {
	return fmt.Sprintf("stackd-elbv2-%x", sha256.Sum256([]byte(resourceKey(spec))))
}
func policyTable(spec Specification) string {
	return fmt.Sprintf("stackd_elbv2_%x", sha256.Sum256([]byte(resourceKey(spec))))
}
func notFound(err error) bool {
	var engine *docker.Error
	return errors.As(err, &engine) && engine.StatusCode == http.StatusNotFound
}

func (d *Docker) inspect(ctx context.Context, name string) (nodeInspection, error) {
	var state nodeInspection
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	return state, err
}

func (s nodeInspection) ownership(spec Specification) error {
	labels := s.Config.Labels
	if s.ID == "" || labels[ownerLabel] != spec.LoadBalancerARN || labels[attachmentLabel] != spec.AttachmentID || labels[identityLabel] == "" ||
		labels[networkLabel] != spec.Network.NetworkID || labels[addressLabel] != spec.Network.Address.String() ||
		labels[callbackHostLabel] != spec.Network.Gateway.String() || !strings.EqualFold(labels[macLabel], spec.Network.MAC) {
		return errors.New("ALB native anchor does not match the retained attachment ownership")
	}
	port, err := strconv.Atoi(labels[callbackPortLabel])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != labels[callbackPortLabel] {
		return errors.New("ALB native anchor has an invalid retained callback")
	}
	return nil
}

func (d *Docker) capabilities(ctx context.Context) error {
	var info struct {
		OSType          string
		SecurityOptions []string
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/info", nil, &info); err != nil {
		return err
	}
	if info.OSType != "linux" {
		return errors.New("ALB requires a local Linux Docker Engine")
	}
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return errors.New("ALB requires rootful Docker without user-namespace remapping")
		}
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(docker.ToolkitImage)+"/json", nil, nil); err != nil {
		return fmt.Errorf("ALB toolkit image must be installed locally (%s): %w", docker.ToolkitImage, err)
	}
	return nil
}

func (d *Docker) Prepare(ctx context.Context, spec Specification) (_ Node, resultErr error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if spec.LoadBalancerARN == "" || spec.AttachmentID == "" || !spec.Network.Address.Is4() || !spec.Network.Gateway.Is4() {
		return nil, errors.New("ALB requires a load balancer ARN, attachment ID and IPv4 attachment")
	}
	mac, err := net.ParseMAC(spec.Network.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return nil, errors.New("ALB attachment requires a unicast Ethernet MAC")
	}
	spec.Network.MAC = mac.String()
	if current := d.nodes[resourceKey(spec)]; current != nil {
		if current.spec.Network.NetworkID != spec.Network.NetworkID || current.spec.Network.Address != spec.Network.Address || current.spec.Network.Gateway != spec.Network.Gateway || current.spec.Network.MAC != spec.Network.MAC {
			return nil, errors.New("ALB attachment identity changed while attached")
		}
		if err := current.SetNetworkPolicy(ctx, spec.Network.Policy); err != nil {
			return nil, err
		}
		return current, nil
	}
	if err := d.capabilities(ctx); err != nil {
		return nil, err
	}
	node := &dockerNode{driver: d, spec: spec, policy: clonePolicy(spec.Network.Policy)}
	fresh, attempted := false, false
	defer func() {
		if resultErr == nil {
			return
		}
		if node.callback != nil {
			resultErr = errors.Join(resultErr, node.detach())
		}
		if !fresh {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if attempted {
			state, err := d.inspect(cleanup, containerName(spec))
			if err == nil {
				if err = state.ownership(spec); err == nil && state.Config.Labels[identityLabel] == node.identity {
					err = d.client.RemoveContainer(cleanup, state.ID)
					if err == nil {
						err = d.removePolicy(cleanup, spec)
					}
				} else if err == nil {
					err = errors.New("ALB create recovery found a different born-owned identity")
				}
			}
			if err != nil && !notFound(err) {
				resultErr = errors.Join(resultErr, err)
				return
			}
		}
		resultErr = errors.Join(resultErr, d.networks.Release(cleanup, spec.Network.NetworkID))
	}()
	err = d.networks.WithBridge(ctx, spec.Network, func(bridge network.Bridge) error {
		node.bridge = bridge
		state, err := d.inspect(ctx, containerName(spec))
		fresh = notFound(err)
		if err != nil && !fresh {
			return fmt.Errorf("inspect ALB native anchor: %w", err)
		}
		address := net.JoinHostPort(spec.Network.Gateway.String(), "0")
		node.identity = rand.Text()
		if !fresh {
			if err := state.ownership(spec); err != nil {
				return err
			}
			if state.Config.Labels[executableLabel] != d.executable || state.Config.Image != docker.ToolkitImage {
				return errors.New("retained ALB native executable or toolkit differs; remove the owned attachment before replacing it")
			}
			address = net.JoinHostPort(spec.Network.Gateway.String(), state.Config.Labels[callbackPortLabel])
			node.id, node.identity = state.ID, state.Config.Labels[identityLabel]
		}
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
		if err != nil {
			return fmt.Errorf("bind exact ALB gateway callback %s: %w", address, err)
		}
		node.callbackAddress = listener.Addr().String()
		node.callback = newCallback(listener, spec.Network.Address, node.identity)
		if fresh {
			_, port, _ := net.SplitHostPort(node.callbackAddress)
			base := docker.ContainerHostConfig{
				NetworkMode: bridge.Name, ReadonlyRootfs: true,
				CapDrop: []string{"ALL"}, CapAdd: []string{"NET_BIND_SERVICE"}, SecurityOpt: []string{"no-new-privileges:true"},
				Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: 128,
				Mounts:    []docker.ContainerMount{{Type: "bind", Source: d.executable, Target: relayExecutable, ReadOnly: true}},
				LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
			}
			// Extend the Engine wire field locally; the shared Docker transport
			// deliberately does not own this service's restart semantics.
			input := struct {
				docker.ContainerConfig
				HostConfig struct {
					docker.ContainerHostConfig
					RestartPolicy struct{ Name string }
				}
			}{ContainerConfig: docker.ContainerConfig{
				Image: docker.ToolkitImage, Entrypoint: []string{relayExecutable},
				Cmd: []string{"--callback", node.callbackAddress, "--token", node.identity},
				Labels: map[string]string{ownerLabel: spec.LoadBalancerARN, attachmentLabel: spec.AttachmentID, identityLabel: node.identity,
					callbackHostLabel: spec.Network.Gateway.String(), callbackPortLabel: port, addressLabel: spec.Network.Address.String(),
					networkLabel: spec.Network.NetworkID, macLabel: spec.Network.MAC, executableLabel: d.executable},
				NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{
					bridge.Name: {MacAddress: spec.Network.MAC, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: spec.Network.Address.String()}},
				}},
			}}
			input.HostConfig.ContainerHostConfig = base
			input.HostConfig.RestartPolicy.Name = "unless-stopped"
			var created struct {
				ID string `json:"Id"`
			}
			attempted = true
			if err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(containerName(spec)), input, &created); err != nil {
				return fmt.Errorf("create ALB native anchor: %w", err)
			}
			node.id = created.ID
			if node.id == "" {
				return errors.New("ALB anchor creation returned no native identity")
			}
		}
		if fresh || (!state.State.Running && !state.State.Paused && !state.State.Restarting && !state.State.Dead) {
			if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(node.id)+"/start", nil, nil); err != nil {
				return fmt.Errorf("start ALB native relay: %w", err)
			}
		}
		state, err = d.inspect(ctx, node.id)
		if err != nil {
			return err
		}
		if err := state.ownership(spec); err != nil {
			return err
		}
		if !state.State.Running || state.State.Paused || state.State.Restarting || state.State.Dead {
			return fmt.Errorf("ALB native relay is not running (%s)", state.State.Status)
		}
		endpoint, ok := state.NetworkSettings.Networks[bridge.Name]
		if !ok || endpoint.IPAddress != spec.Network.Address.String() || endpoint.Gateway != spec.Network.Gateway.String() || !strings.EqualFold(endpoint.MacAddress, spec.Network.MAC) {
			return errors.New("ALB anchor native endpoint differs from retained attachment")
		}
		if err := node.configurePolicy(ctx); err != nil {
			return err
		}
		node.callback.mu.Lock()
		node.callback.refresh = func() {
			refreshCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			node.configurePolicy(refreshCtx)
		}
		node.callback.mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := node.callback.await(readyCtx, nil); err != nil {
		return nil, fmt.Errorf("observe ALB native relay readiness: %w", err)
	}
	d.nodes[resourceKey(spec)] = node
	return node, nil
}

func (n *dockerNode) Listen(ctx context.Context, port int) (net.Listener, error) {
	return n.callback.listen(ctx, port)
}
func (n *dockerNode) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.callback.dial(ctx, network, address)
}
func (n *dockerNode) Close() error {
	n.driver.mu.Lock()
	defer n.driver.mu.Unlock()
	if n.driver.nodes[resourceKey(n.spec)] == n {
		delete(n.driver.nodes, resourceKey(n.spec))
	}
	return n.detach()
}

func (n *dockerNode) detach() error {
	n.policyMu.Lock()
	defer n.policyMu.Unlock()
	return n.callback.close()
}

func (d *Docker) Remove(ctx context.Context, spec Specification) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if spec.LoadBalancerARN == "" || spec.AttachmentID == "" {
		return errors.New("ALB removal requires exact load balancer and attachment identities")
	}
	state, err := d.inspect(ctx, containerName(spec))
	if err != nil && !notFound(err) {
		return err
	}
	if err == nil {
		if err := state.ownership(spec); err != nil {
			return err
		}
		if node := d.nodes[resourceKey(spec)]; node != nil && node.identity != state.Config.Labels[identityLabel] {
			return errors.New("ALB native anchor born-owned identity changed")
		}
	}
	if node := d.nodes[resourceKey(spec)]; node != nil {
		if err := node.detach(); err != nil {
			return err
		}
		delete(d.nodes, resourceKey(spec))
	}
	// Keep the packet boundary until the exact owned endpoint is gone.
	if state.ID != "" {
		if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
			return err
		}
	}
	if err := d.removePolicy(ctx, spec); err != nil {
		return err
	}
	return d.networks.Release(ctx, spec.Network.NetworkID)
}

var _ Runtime = (*Docker)(nil)
var _ Node = (*dockerNode)(nil)
