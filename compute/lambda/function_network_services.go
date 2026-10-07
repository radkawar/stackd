package lambda

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
)

const endpointBackendPortLabel = "stackd.lambda.endpoint-backend-port"
const endpointBackendHostLabel = "stackd.lambda.endpoint-backend-host"

// FunctionServiceEndpoints materializes EC2 endpoint ENIs and their real packet
// listeners, never a second network resource store. Each endpoint request retains
// its original Host, path, headers and body through a raw TCP tunnel to the actual
// AWS HTTP handler. Interface endpoints listen on TCP 443; the local HTTP scheme
// matches stackd's emulator endpoint, without pretending to terminate AWS TLS.
type FunctionServiceEndpoints struct {
	runtime   *FunctionNetworkRuntime
	nodes     []*functionServiceNode
	variables map[string]string
	closed    bool // protected by runtime.serviceMu
}

type functionServiceNode struct {
	key, owner, container string
	endpoint              network.ServiceEndpoint
	attachment            *FunctionNetworkAttachment
	listener              net.Listener
	server                *http.Server
	refs                  int
	containerRemoved      bool
	ready                 bool
	closed                bool
}

func serviceVariable(service string) string {
	switch service {
	case "logs":
		return "AWS_ENDPOINT_URL_CLOUDWATCH_LOGS"
	case "bedrock-runtime":
		return "AWS_ENDPOINT_URL_BEDROCK_RUNTIME"
	default:
		return "AWS_ENDPOINT_URL_" + strings.ToUpper(service)
	}
}

func (r *FunctionNetworkRuntime) OpenServices(ctx context.Context, specification network.Specification, handler func(network.ServiceEndpoint) http.Handler) (*FunctionServiceEndpoints, error) {
	r.serviceMu.Lock()
	defer r.serviceMu.Unlock()
	lease := &FunctionServiceEndpoints{runtime: r, variables: make(map[string]string)}
	for _, endpoint := range specification.ServiceEndpoints {
		key := "interface/" + endpoint.Network.NetworkID + "/" + endpoint.ID + "/" + endpoint.Network.Address.String()
		address := endpoint.Network.Address.String()
		if endpoint.Kind == "Gateway" {
			key = "gateway/" + specification.NetworkID
			address = specification.Gateway.String()
		}
		node := r.services[key]
		if node != nil && !node.ready {
			return lease, errors.New("native service endpoint cleanup is pending")
		}
		if node == nil {
			physical := endpoint
			if endpoint.Kind == "Gateway" {
				physical.ID, physical.Service = "", ""
			}
			var err error
			node, err = r.openServiceNode(ctx, key, physical, handler(physical))
			if node != nil {
				r.services[key] = node
				node.refs++
				lease.nodes = append(lease.nodes, node)
			}
			if err != nil {
				return lease, err
			}
		}
		if !slices.Contains(lease.nodes, node) {
			node.refs++
			lease.nodes = append(lease.nodes, node)
		}
		if endpoint.Kind == "Gateway" || endpoint.PrivateDNS {
			variable := serviceVariable(endpoint.Service)
			if _, exists := lease.variables[variable]; !exists {
				lease.variables[variable] = "http://" + net.JoinHostPort(address, "443")
			}
		}
	}
	return lease, nil
}

func (r *FunctionNetworkRuntime) openServiceNode(ctx context.Context, key string, endpoint network.ServiceEndpoint, handler http.Handler) (*functionServiceNode, error) {
	if handler == nil {
		return nil, errors.New("lambda VPC endpoints require the actual authenticated AWS HTTP handler")
	}
	owner := "lambda-service-endpoint/" + key
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(r.namespace+"\x00"+owner)))
	node := &functionServiceNode{key: key, owner: owner, container: "stackd-lambda-endpoint-" + identity, endpoint: endpoint}
	var previous struct {
		Config struct {
			Labels map[string]string
			Cmd    []string
			Image  string
		}
		State           struct{ Running bool }
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress, MacAddress string }
		}
	}
	err := r.client.JSON(ctx, http.MethodGet, "/containers/"+node.container+"/json", nil, &previous)
	retained := err == nil
	if err != nil && !sourceNetworkMissing(err) {
		return nil, err
	}
	listen := r.controllerListen
	if retained {
		if previous.Config.Labels[functionNetworkLabel] != owner || previous.Config.Labels[functionNetworkOwnerLabel] != r.namespace || previous.Config.Labels[endpointBackendHostLabel] != r.controllerHost || previous.Config.Image != docker.ToolkitImage {
			return nil, errors.New("native service endpoint belongs to another controller or callback target")
		}
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, err
		}
		listen = net.JoinHostPort(host, previous.Config.Labels[endpointBackendPortLabel])
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("claim native endpoint controller listener: %w", err)
	}
	node.listener = listener
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		return nil, err
	}
	labels := map[string]string{functionNetworkLabel: owner, functionNetworkOwnerLabel: r.namespace, endpointBackendPortLabel: port, endpointBackendHostLabel: r.controllerHost}
	callback := net.JoinHostPort(r.controllerHost, port)
	config := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: []string{"socat"}, Labels: labels, HostConfig: docker.ContainerHostConfig{ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_BIND_SERVICE"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 64, LogConfig: docker.ContainerLogConfig{Type: "none"}}}
	if endpoint.Kind == "Gateway" {
		if err := r.bridges.WithBridge(ctx, endpoint.Network, func(network.Bridge) error { return nil }); err != nil {
			return node, err
		}
		target := r.controllerHost
		if target == "" {
			target = endpoint.Network.Gateway.String()
		}
		config.HostConfig.NetworkMode = "host"
		config.Cmd = []string{"TCP4-LISTEN:443,bind=" + endpoint.Network.Gateway.String() + ",range=" + endpoint.Network.Pool.String() + ",reuseaddr,fork", "TCP:" + net.JoinHostPort(target, port) + ",connect-timeout=5"}
	} else {
		node.attachment = r.Prepare(owner, endpoint.Network)
		config.Cmd = []string{"TCP4-LISTEN:443,reuseaddr,fork", "TCP4:" + net.JoinHostPort(endpoint.Network.Gateway.String(), port) + ",connect-timeout=5"}
		if err := node.attachment.Configure(ctx, &config, callback); err != nil {
			return node, err
		}
	}
	if retained {
		if !slices.Equal(previous.Config.Cmd, config.Cmd) {
			return node, errors.New("retained native service endpoint differs from its exact controller tunnel")
		}
	} else if err := r.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(node.container), config, nil); err != nil {
		return node, err
	}
	if !retained || !previous.State.Running {
		if err := r.client.JSON(ctx, http.MethodPost, "/containers/"+node.container+"/start", nil, nil); err != nil {
			return node, err
		}
	}
	if node.attachment != nil {
		if err := node.attachment.Attach(ctx, node.container); err != nil {
			return node, err
		}
	}
	node.server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 64 << 10}
	node.ready = true
	go func() { _ = node.server.Serve(listener) }()
	return node, nil
}

func (l *FunctionServiceEndpoints) EndpointVariables() map[string]string {
	out := make(map[string]string, len(l.variables))
	for key, value := range l.variables {
		out[key] = value
	}
	return out
}

func (l *FunctionServiceEndpoints) SetPolicy(ctx context.Context, endpoints []network.ServiceEndpoint, observe func(context.Context, network.ServiceEndpoint) (network.Specification, bool, error)) error {
	l.runtime.serviceMu.Lock()
	defer l.runtime.serviceMu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	for _, node := range l.nodes {
		if node.attachment == nil || node.closed {
			continue
		}
		var specification network.Specification
		found := false
		for _, current := range endpoints {
			if current.ID == node.endpoint.ID && current.Network.Address == node.endpoint.Network.Address {
				specification, found = current.Network, true
				break
			}
		}
		if !found {
			var err error
			specification, found, err = observe(ctx, node.endpoint)
			if err != nil {
				return err
			}
		}
		if !found {
			if err := l.runtime.closeServiceNode(ctx, node); err != nil {
				return err
			}
			if l.runtime.services[node.key] == node {
				delete(l.runtime.services, node.key)
			}
			continue
		}
		if err := node.attachment.SetPolicy(ctx, specification); err != nil {
			return errors.Join(err, node.attachment.RevokeTimeout(ctx))
		}
	}
	return nil
}

func (l *FunctionServiceEndpoints) Close(ctx context.Context) error {
	l.runtime.serviceMu.Lock()
	defer l.runtime.serviceMu.Unlock()
	if l.closed {
		return nil
	}
	retained := l.nodes[:0]
	var errs []error
	for _, node := range l.nodes {
		if node.refs > 1 {
			node.refs--
			continue
		}
		if err := l.runtime.closeServiceNode(ctx, node); err != nil {
			errs = append(errs, err)
			retained = append(retained, node)
			continue
		}
		if l.runtime.services[node.key] == node {
			delete(l.runtime.services, node.key)
		}
	}
	l.nodes = retained
	if len(retained) == 0 {
		l.closed = true
	}
	return errors.Join(errs...)
}

func (r *FunctionNetworkRuntime) closeServiceNode(ctx context.Context, node *functionServiceNode) error {
	if node.closed {
		return nil
	}
	if !node.containerRemoved {
		var info sourceContainerInfo
		err := r.client.JSON(ctx, http.MethodGet, "/containers/"+node.container+"/json", nil, &info)
		if err != nil && !sourceNetworkMissing(err) {
			return err
		}
		if err == nil {
			if info.Config.Labels[functionNetworkLabel] != node.owner || info.Config.Labels[functionNetworkOwnerLabel] != r.namespace {
				return errors.New("native endpoint cleanup owner differs")
			}
			if err := r.client.RemoveContainer(ctx, node.container); err != nil {
				return err
			}
		}
		node.containerRemoved = true
	}
	if node.attachment != nil {
		if err := node.attachment.Close(ctx); err != nil {
			return err
		}
	}
	if node.server != nil {
		_ = node.server.Close()
	} else if node.listener != nil {
		_ = node.listener.Close()
	}
	node.closed = true
	return nil
}
