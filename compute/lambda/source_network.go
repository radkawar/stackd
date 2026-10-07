package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
)

const sourceNetworkLabel = "stackd.lambda.source-network"
const sourceNetworkOwnerLabel = "stackd.lambda.source-network-owner"
const sourceNetworkVPCLabel = "stackd.lambda.source-network-vpc"

// SourceNetworkAttachment supplies sockets created inside an isolated namespace
// and applies EC2-authoritative packet policy outside that namespace.
type SourceNetworkAttachment interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	SetPolicy(context.Context, network.Specification) error
	Revoke()
	Close() error
}

// SourceNetworkRuntime owns only Lambda poller namespaces. Namespace must be the
// controller's persistent instance identity, not a process-specific random ID.
// The selected local Docker Engine and native bridges enforce EC2 packet policy.
type SourceNetworkRuntime struct {
	client    *docker.Client
	bridges   *network.Bridges
	namespace string
	mu        sync.Mutex
	active    map[string]*sourceNetworkAttachment
}

func NewSourceNetworkRuntime(client *docker.Client, bridges *network.Bridges, namespace string) (*SourceNetworkRuntime, error) {
	if client == nil || bridges == nil || namespace == "" {
		return nil, errors.New("lambda source networking requires Docker, shared native bridges and a persistent instance identity")
	}
	return &SourceNetworkRuntime{client: client, bridges: bridges, namespace: namespace, active: make(map[string]*sourceNetworkAttachment)}, nil
}

func (r *SourceNetworkRuntime) identity(mapping string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(r.namespace+"\x00"+mapping)))
}
func (r *SourceNetworkRuntime) container(mapping string) string {
	return "stackd-lambda-source-" + r.identity(mapping)
}
func (r *SourceNetworkRuntime) table(mapping string) string {
	return "stackd_lambda_" + r.identity(mapping)
}
func (r *SourceNetworkRuntime) owner(mapping string) string { return r.namespace + "\x00" + mapping }

func (r *SourceNetworkRuntime) Attach(ctx context.Context, mapping string, spec network.Specification) (SourceNetworkAttachment, error) {
	if mapping == "" {
		return nil, errors.New("lambda source namespace requires an immutable mapping ARN")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.active[mapping]; a != nil {
		if err := a.SetPolicy(ctx, spec); err != nil {
			return nil, err
		}
		return a.lease(), nil
	}
	a := &sourceNetworkAttachment{runtime: r, mapping: mapping, spec: spec, connections: make(map[*sourceProxyConn]struct{}), leases: make(map[*sourceNetworkLease]struct{})}
	err := r.bridges.WithBridge(ctx, spec, func(bridge network.Bridge) error {
		a.bridge = bridge
		if err := r.prepareContainer(ctx, mapping, spec, bridge); err != nil {
			return err
		}
		peer, err := r.peer(ctx, mapping, bridge)
		if err != nil {
			return err
		}
		a.peer = peer
		return a.install(ctx, spec)
	})
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		// A rejected create has no container label from which release can
		// recover the VPC. Retire that empty bridge using the admitted spec.
		return nil, errors.Join(err, r.release(cleanup, mapping), r.bridges.Release(cleanup, spec.NetworkID))
	}
	r.active[mapping] = a
	return a.lease(), nil
}

type sourceContainerInfo struct {
	Config          struct{ Labels map[string]string }
	State           struct{ Running bool }
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress, MacAddress string }
	}
}

func (r *SourceNetworkRuntime) inspect(ctx context.Context, mapping string) (sourceContainerInfo, error) {
	var info sourceContainerInfo
	err := r.client.JSON(ctx, http.MethodGet, "/containers/"+r.container(mapping)+"/json", nil, &info)
	if err == nil && (info.Config.Labels[sourceNetworkLabel] != mapping || info.Config.Labels[sourceNetworkOwnerLabel] != r.namespace) {
		err = errors.New("native source namespace ownership differs from mapping")
	}
	return info, err
}
func sourceNetworkMissing(err error) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound
}
func (r *SourceNetworkRuntime) prepareContainer(ctx context.Context, mapping string, spec network.Specification, bridge network.Bridge) error {
	info, err := r.inspect(ctx, mapping)
	if err != nil && !sourceNetworkMissing(err) {
		return err
	}
	if err == nil {
		endpoint, ok := info.NetworkSettings.Networks[bridge.Name]
		if info.Config.Labels[sourceNetworkVPCLabel] != spec.NetworkID || !ok || endpoint.IPAddress != spec.Address.String() || !strings.EqualFold(endpoint.MacAddress, spec.MAC) {
			return errors.New("retained source namespace differs from authoritative EC2 attachment")
		}
		if info.State.Running {
			return nil
		}
		return r.client.JSON(ctx, http.MethodPost, "/containers/"+r.container(mapping)+"/start", nil, nil)
	}
	var dns []string
	for _, address := range spec.DNS {
		dns = append(dns, address.String())
	}
	if len(dns) == 0 {
		dns = []string{"127.0.0.1"}
	} // No ambient host resolver fallback.
	type hostConfig struct {
		docker.ContainerHostConfig
		DNS       []string `json:"Dns"`
		DNSSearch []string `json:"DnsSearch"`
	}
	config := struct {
		docker.ContainerConfig
		HostConfig hostConfig
	}{
		ContainerConfig: docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"sleep", "infinity"},
			Labels:           map[string]string{sourceNetworkLabel: mapping, sourceNetworkOwnerLabel: r.namespace, sourceNetworkVPCLabel: spec.NetworkID},
			NetworkingConfig: &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{bridge.Name: {MacAddress: spec.MAC, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: spec.Address.String()}}}}},
		HostConfig: hostConfig{ContainerHostConfig: docker.ContainerHostConfig{NetworkMode: bridge.Name, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: 128, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}}, DNS: dns, DNSSearch: []string{"."}},
	}
	if err := r.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(r.container(mapping)), config, nil); err != nil {
		return err
	}
	return r.client.JSON(ctx, http.MethodPost, "/containers/"+r.container(mapping)+"/start", nil, nil)
}
func (r *SourceNetworkRuntime) helper(ctx context.Context, mapping, mode string, command []string) ([]byte, error) {
	return docker.RunHelper(ctx, r.client, "lambda-source-network", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: command, Labels: map[string]string{sourceNetworkLabel: mapping, sourceNetworkOwnerLabel: r.namespace}, HostConfig: docker.ContainerHostConfig{NetworkMode: mode, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}}})
}
func (r *SourceNetworkRuntime) peer(ctx context.Context, mapping string, bridge network.Bridge) (string, error) {
	out, err := r.helper(ctx, mapping, "container:"+r.container(mapping), []string{"cat", "/sys/class/net/eth0/iflink"})
	if err != nil {
		return "", err
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || index <= 0 {
		return "", errors.New("source namespace has no valid external veth index")
	}
	out, err = r.helper(ctx, mapping, "host", []string{"ip", "-d", "-j", "link", "show", "master", bridge.Device})
	if err != nil {
		return "", err
	}
	var links []struct {
		Index  int    `json:"ifindex"`
		Name   string `json:"ifname"`
		Master string `json:"master"`
		Info   struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return "", err
	}
	for _, link := range links {
		if link.Index == index && link.Master == bridge.Device && link.Info.Kind == "veth" {
			return link.Name, nil
		}
	}
	return "", errors.New("source namespace lacks an owned external veth; refusing unfiltered dialing")
}

// Release verifies native labels before removing only this mapping's namespace,
// packet-policy tables and (when empty) the shared VPC bridge.
func (r *SourceNetworkRuntime) Release(ctx context.Context, mapping string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.active[mapping]; a != nil {
		a.mu.Lock()
		a.closed = true
		a.revokeLocked()
		a.mu.Unlock()
		delete(r.active, mapping)
	}
	return r.release(ctx, mapping)
}
func (r *SourceNetworkRuntime) release(ctx context.Context, mapping string) error {
	info, err := r.inspect(ctx, mapping)
	if err != nil && !sourceNetworkMissing(err) {
		return err
	}
	if err == nil {
		if err := r.client.RemoveContainer(ctx, r.container(mapping)); err != nil {
			return err
		}
	}
	if err := r.bridges.RemovePolicy(ctx, r.table(mapping), r.owner(mapping)); err != nil {
		return err
	}
	if vpc := info.Config.Labels[sourceNetworkVPCLabel]; vpc != "" {
		return r.bridges.Release(ctx, vpc)
	}
	return nil
}

type sourceNetworkAttachment struct {
	runtime     *SourceNetworkRuntime
	mapping     string
	mu          sync.Mutex
	spec        network.Specification
	bridge      network.Bridge
	peer        string
	closed      bool
	connections map[*sourceProxyConn]struct{}
	leases      map[*sourceNetworkLease]struct{}
}

func (a *sourceNetworkAttachment) install(ctx context.Context, spec network.Specification) error {
	if !spec.Policy.Subnet.IsValid() || !spec.Policy.Subnet.Contains(spec.Address) {
		return errors.New("source policy requires the authoritative containing subnet")
	}
	return a.runtime.bridges.ApplyPolicy(ctx, a.runtime.table(a.mapping), spec, spec.Policy, a.peer, network.Options{PublicOwner: a.runtime.owner(a.mapping)}, a.bridge)
}
func (a *sourceNetworkAttachment) SetPolicy(ctx context.Context, spec network.Specification) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return net.ErrClosed
	}
	if spec.NetworkID != a.spec.NetworkID || spec.Address != a.spec.Address || spec.Pool != a.spec.Pool || spec.Gateway != a.spec.Gateway || spec.MAC != a.spec.MAC {
		return errors.New("EC2 source attachment identity changed")
	}
	if a.spec.Policy.Equal(spec.Policy) {
		return nil
	}
	a.revokeLocked()
	if err := a.install(ctx, spec); err != nil {
		return err
	}
	a.spec = spec
	return nil
}
func (a *sourceNetworkAttachment) revokeLocked() {
	for conn := range a.connections {
		conn.abort()
	}
	clear(a.connections)
}
