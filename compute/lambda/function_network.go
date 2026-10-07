package lambda

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
)

// FunctionNetworkLease belongs to one execution environment. Configure applies
// placement to its trusted storage keeper; Attach installs policy before customer
// processes start. Close follows removal of all containers sharing that namespace.
type FunctionNetworkLease interface {
	Configure(context.Context, *docker.ContainerConfig, string) error
	Attach(context.Context, string) error
	BindExecutionCredential(string)
	EndpointVariables() map[string]string
	Check(context.Context) error
	Close(context.Context) error
}

const functionNetworkLabel = "stackd.lambda.function-network"
const functionNetworkOwnerLabel = "stackd.lambda.function-network-owner"

// FunctionNetworkRuntime uses a rootful Linux daemon's bridge and nftables
// facilities. NewDaemonBridges supports Darwin/Docker Desktop and remote clients
// through daemon-owned helper locks; NewBridges retains local host-lock semantics.
// Rootless/userns-remapped and non-Linux engines return capability errors.
// Non-VPC Lambda execution does not require this runtime.
type FunctionNetworkRuntime struct {
	client                           *docker.Client
	bridges                          *network.Bridges
	namespace                        string
	serviceMu                        sync.Mutex
	services                         map[string]*functionServiceNode
	controllerListen, controllerHost string
	dns                              []string
}

func NewFunctionNetworkRuntime(client *docker.Client, bridges *network.Bridges, namespace string) (*FunctionNetworkRuntime, error) {
	if client == nil || bridges == nil || namespace == "" {
		return nil, errors.New("lambda function VPC networking requires Docker, native bridges and a persistent instance identity")
	}
	return &FunctionNetworkRuntime{client: client, bridges: bridges, namespace: namespace, controllerListen: "0.0.0.0:0", services: make(map[string]*functionServiceNode)}, nil
}

// Prepare reserves no second address registry: EC2 supplied the immutable
// reservation and the native endpoint itself owns bridge lifetime.
func (r *FunctionNetworkRuntime) Prepare(owner string, spec network.Specification) *FunctionNetworkAttachment {
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(r.namespace+"\x00"+owner)))
	return &FunctionNetworkAttachment{runtime: r, owner: owner, table: "stackd_lambda_" + identity, spec: spec}
}

type FunctionNetworkAttachment struct {
	runtime                                        *FunctionNetworkRuntime
	mu                                             sync.Mutex
	owner, table, container, peer, callback, relay string
	bridge                                         network.Bridge
	spec                                           network.Specification
	configured, attached, revoked, closed          bool
}

func (a *FunctionNetworkAttachment) Configure(ctx context.Context, config *docker.ContainerConfig, callback string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.revoked {
		return net.ErrClosed
	}
	if a.configured {
		return errors.New("lambda function namespace is already configured")
	}
	host, port, err := net.SplitHostPort(callback)
	if err != nil || strings.ContainsAny(host, ",\r\n\x00/ \t") {
		return errors.New("lambda function callback address is invalid")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("lambda function callback port is invalid")
	}
	if err := a.runtime.bridges.WithBridge(ctx, a.spec, func(bridge network.Bridge) error {
		a.bridge = bridge
		return nil
	}); err != nil {
		return err
	}
	a.configured = true
	a.callback = net.JoinHostPort(a.spec.Gateway.String(), port)
	config.MacAddress = a.spec.MAC
	config.HostConfig.NetworkMode = a.bridge.Name
	config.NetworkingConfig = &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{a.bridge.Name: {IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: a.spec.Address.String()}}}}
	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}
	config.Labels[functionNetworkLabel] = a.owner
	config.Labels[functionNetworkOwnerLabel] = a.runtime.namespace
	config.HostConfig.DNS, err = a.functionDNS(ctx, a.spec)
	if err != nil {
		return err
	}
	config.HostConfig.DNSSearch = []string{"."}
	// Only the authenticated per-environment Runtime API listener is exempt
	// from SG/NACL policy. The customer AWS endpoint receives no exemption.
	for i, extra := range config.HostConfig.ExtraHosts {
		name, _, ok := strings.Cut(extra, ":")
		if ok && strings.HasSuffix(name, ".runtime.internal") {
			config.HostConfig.ExtraHosts[i] = name + ":" + a.spec.Gateway.String()
		}
	}
	if host != "" && host != a.spec.Gateway.String() {
		a.relay = "stackd-lambda-callback-" + strings.TrimPrefix(a.table, "stackd_lambda_")
		target := "TCP4:" + net.JoinHostPort(host, port) + ",connect-timeout=5"
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			target = "TCP6:" + net.JoinHostPort(host, port) + ",connect-timeout=5"
		}
		relay := docker.ContainerConfig{
			Image: docker.ToolkitImage, Entrypoint: []string{"socat"},
			Cmd:        []string{"TCP4-LISTEN:" + port + ",bind=" + a.spec.Gateway.String() + ",range=" + a.spec.Address.String() + "/32,reuseaddr,fork", target},
			Labels:     maps.Clone(config.Labels),
			HostConfig: docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 64, LogConfig: docker.ContainerLogConfig{Type: "none"}},
		}
		if err := a.prepareRelay(ctx, relay); err != nil {
			return err
		}
	}
	return nil
}

func (a *FunctionNetworkAttachment) helper(ctx context.Context, mode string, command []string) ([]byte, error) {
	// RunHelper collects stdout/stderr through Engine logs after completion.
	return docker.RunHelper(ctx, a.runtime.client, "lambda-function-network", docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: command, Labels: map[string]string{functionNetworkLabel: a.owner, functionNetworkOwnerLabel: a.runtime.namespace}, HostConfig: docker.ContainerHostConfig{NetworkMode: mode, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}}})
}

func (a *FunctionNetworkAttachment) Attach(ctx context.Context, container string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.revoked {
		return net.ErrClosed
	}
	if !a.configured || a.attached || container == "" {
		return errors.New("lambda function namespace is not ready for attachment")
	}
	var info sourceContainerInfo
	if err := a.runtime.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(container)+"/json", nil, &info); err != nil {
		return err
	}
	endpoint, exists := info.NetworkSettings.Networks[a.bridge.Name]
	if !info.State.Running || info.Config.Labels[functionNetworkLabel] != a.owner || info.Config.Labels[functionNetworkOwnerLabel] != a.runtime.namespace || !exists || endpoint.IPAddress != a.spec.Address.String() || !strings.EqualFold(endpoint.MacAddress, a.spec.MAC) || len(info.NetworkSettings.Networks) != 1 {
		return errors.New("lambda function namespace differs from its authoritative EC2 attachment")
	}
	a.container = container
	out, err := a.helper(ctx, "container:"+container, []string{"cat", "/sys/class/net/eth0/iflink"})
	if err != nil {
		return err
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || index <= 0 {
		return errors.New("lambda function namespace has no valid external veth index")
	}
	out, err = a.helper(ctx, "host", []string{"ip", "-d", "-j", "link", "show", "master", a.bridge.Device})
	if err != nil {
		return err
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
		return err
	}
	for _, link := range links {
		if link.Index == index && link.Master == a.bridge.Device && link.Info.Kind == "veth" {
			a.peer = link.Name
			break
		}
	}
	if a.peer == "" {
		return errors.New("lambda function namespace lacks an owned external veth")
	}
	if err := a.install(ctx, a.spec); err != nil {
		return err
	}
	a.attached = true
	return nil
}

func (a *FunctionNetworkAttachment) install(ctx context.Context, spec network.Specification) error {
	if !spec.Policy.Subnet.IsValid() || !spec.Policy.Subnet.Contains(spec.Address) {
		return errors.New("lambda function policy requires its authoritative containing subnet")
	}
	for _, route := range spec.Policy.NATRoutes {
		if route.Allowed {
			if err := a.runtime.bridges.VerifyPrivateEgress(ctx, spec.NetworkID); err != nil {
				return err
			}
			break
		}
	}
	return a.runtime.bridges.ApplyPolicy(ctx, a.table, spec, spec.Policy, a.peer, network.Options{Callback: a.callback, PublicOwner: a.runtime.namespace + "\x00" + a.owner}, a.bridge)
}

func (a *FunctionNetworkAttachment) SetPolicy(ctx context.Context, spec network.Specification) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.revoked {
		return net.ErrClosed
	}
	if spec.NetworkID != a.spec.NetworkID || spec.Address != a.spec.Address || spec.Pool != a.spec.Pool || spec.Gateway != a.spec.Gateway || spec.MAC != a.spec.MAC {
		return errors.New("EC2 function attachment identity changed")
	}
	if a.configured && (spec.DNSSupport != a.spec.DNSSupport || !slices.Equal(spec.DNS, a.spec.DNS)) {
		return errors.New("EC2 function DNS authority changed; the namespace must be replaced")
	}
	if a.attached && !a.spec.Policy.Equal(spec.Policy) {
		if err := a.install(ctx, spec); err != nil {
			return err
		}
	}
	a.spec = spec
	return nil
}

// Revoke withdraws packet authority, not merely controller sockets. If native
// policy replacement fails, disconnect the owned Docker endpoint instead.
func (a *FunctionNetworkAttachment) Revoke(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.revoked {
		return nil
	}
	if !a.attached {
		a.revoked = true
		return nil
	}
	deny := a.spec
	deny.Policy = network.Policy{Subnet: a.spec.Policy.Subnet}
	if err := a.install(ctx, deny); err != nil {
		request := struct {
			Container string
			Force     bool
		}{a.container, true}
		if disconnect := a.runtime.client.JSON(ctx, http.MethodPost, "/networks/"+url.PathEscape(a.bridge.Name)+"/disconnect", request, nil); disconnect != nil {
			return errors.Join(err, disconnect)
		}
	}
	a.revoked = true
	return nil
}

func (a *FunctionNetworkAttachment) Close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	// Caller has already removed every customer namespace sharer.
	if a.relay != "" {
		var info sourceContainerInfo
		err := a.runtime.client.JSON(ctx, http.MethodGet, "/containers/"+a.relay+"/json", nil, &info)
		if err != nil && !sourceNetworkMissing(err) {
			return err
		}
		if err == nil {
			if info.Config.Labels[functionNetworkLabel] != a.owner || info.Config.Labels[functionNetworkOwnerLabel] != a.runtime.namespace {
				return errors.New("lambda callback relay belongs to another native attachment")
			}
			if err := a.runtime.client.RemoveContainer(ctx, a.relay); err != nil {
				return err
			}
		}
		a.relay = ""
	}
	if a.configured {
		if err := a.runtime.bridges.RemovePolicy(ctx, a.table, a.runtime.namespace+"\x00"+a.owner); err != nil {
			return err
		}
		if err := a.runtime.bridges.Release(ctx, a.spec.NetworkID); err != nil {
			return err
		}
	}
	a.closed = true
	return nil
}

// RevokeTimeout bounds policy withdrawal independently of caller cancellation.
func (a *FunctionNetworkAttachment) RevokeTimeout(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	return a.Revoke(cleanup)
}

// HasEndpoint reads native ownership, including stopped retained keepers. A
// relay or helper alone is not a customer ENI endpoint and cannot pin recovery.
func (r *FunctionNetworkRuntime) HasEndpoint(ctx context.Context, owner string, spec network.Specification) (bool, error) {
	filters, err := json.Marshal(map[string][]string{"label": {functionNetworkLabel + "=" + owner, functionNetworkOwnerLabel + "=" + r.namespace}})
	if err != nil {
		return false, err
	}
	var containers []struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress, MacAddress string }
		}
	}
	if err := r.client.JSON(ctx, http.MethodGet, "/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil, &containers); err != nil {
		return false, err
	}
	for _, container := range containers {
		for _, endpoint := range container.NetworkSettings.Networks {
			if endpoint.IPAddress == spec.Address.String() && strings.EqualFold(endpoint.MacAddress, spec.MAC) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Retire is called only after native ownership proves no ENI endpoint remains.
// Reconstructed identities match the original function execution incarnation.
func (r *FunctionNetworkRuntime) Retire(ctx context.Context, owner string, spec network.Specification) error {
	attachment := r.Prepare(owner, spec)
	attachment.configured = true
	attachment.relay = "stackd-lambda-callback-" + strings.TrimPrefix(attachment.table, "stackd_lambda_")
	return attachment.Close(ctx)
}

func (r *FunctionNetworkRuntime) SetControllerAddress(listenAddress, callbackHost string) error {
	if listenAddress == "" {
		listenAddress = "0.0.0.0:0"
	}
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil || strings.ContainsAny(callbackHost, ",\r\n\x00/ \t") {
		return errors.New("lambda network controller callback address is invalid")
	}
	r.controllerListen, r.controllerHost = net.JoinHostPort(host, "0"), callbackHost
	return nil
}

func (a *FunctionNetworkAttachment) prepareRelay(ctx context.Context, config docker.ContainerConfig) error {
	var info struct {
		Config struct {
			Labels map[string]string
			Cmd    []string
			Image  string
		}
		State struct{ Running bool }
	}
	err := a.runtime.client.JSON(ctx, http.MethodGet, "/containers/"+a.relay+"/json", nil, &info)
	if err != nil && !sourceNetworkMissing(err) {
		return err
	}
	if err == nil {
		if info.Config.Labels[functionNetworkLabel] != a.owner || info.Config.Labels[functionNetworkOwnerLabel] != a.runtime.namespace || info.Config.Image != config.Image || !slices.Equal(info.Config.Cmd, config.Cmd) {
			return errors.New("retained Lambda callback relay differs from its native owner and target")
		}
		if info.State.Running {
			return nil
		}
	} else if err := a.runtime.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(a.relay), config, nil); err != nil {
		return err
	}
	return a.runtime.client.JSON(ctx, http.MethodPost, "/containers/"+a.relay+"/start", nil, nil)
}
