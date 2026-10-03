package eks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ownerLabel = "stackd.eks.owner"
const idLabel = "stackd.eks.id"

type dockerContainer struct {
	ID     string `json:"Id"`
	Name   string
	Config struct {
		Labels map[string]string
		Image  string
		Cmd    []string
	}
	State      struct{ Running bool }
	HostConfig struct {
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
	}
	Mounts          []struct{ Type, Name, Source, Destination string }
	NetworkSettings struct {
		Networks map[string]struct{ NetworkID string }
	}
}

func (k *K3d) ownedContainers(ctx context.Context, state diskState) ([]dockerContainer, error) {
	// Inspect both name and k3d cluster label: neither alone establishes ownership.
	ids := make(map[string]bool)
	for _, filter := range []string{"name=k3d-" + state.Name + "-", "label=k3d.cluster=" + state.Name} {
		out, err := k.command(ctx, "docker", "container", "ls", "-aq", "--no-trunc", "--filter", filter)
		if err != nil {
			return nil, err
		}
		for _, id := range strings.Fields(string(out)) {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	args := []string{"container", "inspect"}
	for id := range ids {
		args = append(args, id)
	}
	out, err := k.command(ctx, "docker", args...)
	if err != nil {
		return nil, err
	}
	var containers []dockerContainer
	if err = json.Unmarshal(out, &containers); err != nil {
		return nil, err
	}
	for _, container := range containers {
		labels := container.Config.Labels
		if container.Name == "/k3d-"+state.Name+"-tools" {
			// k3d's auxiliary tools node cannot take custom runtime labels.
			// Its authority must instead be rooted in BOTH exact-owned native
			// resources, not its name or k3d cluster label alone.
			volume, err := k.ownedVolume(ctx, state)
			if err != nil {
				return nil, err
			}
			network, err := k.ownedNetwork(ctx, state)
			if err != nil {
				return nil, err
			}
			mounted := false
			for _, mount := range container.Mounts {
				if volume != "" && mount.Name == volume && mount.Destination == "/k3d/images" {
					mounted = true
				}
			}
			if labels["k3d.cluster"] != state.Name || container.Config.Image != "ghcr.io/k3d-io/k3d-tools:5.8.3" || !mounted || network == "" || container.NetworkSettings.Networks[state.Name].NetworkID != network {
				return nil, errors.New("eks: refusing unowned k3d tools node")
			}
			continue
		}
		if k.ownedFargateContainer(state, container) {
			continue
		}
		image, _ := PinnedImage(state.InitialVersion)
		server := container.Name == "/k3d-"+state.Name+"-server-0"
		worker := container.Name == "/k3d-"+state.Name+"-agent-0"
		if labels[ownerLabel] != state.Token || labels[idLabel] != state.ID || labels["k3d.cluster"] != state.Name || (!server && !worker) || container.Config.Image != image {
			return nil, errors.New("eks: refusing native cluster with unowned or unexpected containers")
		}
		if server {
			bindings := container.HostConfig.PortBindings["6443/tcp"]
			if len(bindings) != 1 || bindings[0].HostIP != state.nativeHost() || bindings[0].HostPort != fmt.Sprint(state.NativePort) {
				return nil, errors.New("eks: native API binding differs from its retained owned endpoint")
			}
		} else if err := k.validateWorkerTransport(state, container); err != nil {
			return nil, err
		}
	}
	return containers, nil
}

func (k *K3d) ownedNetwork(ctx context.Context, state diskState) (string, error) {
	out, err := k.command(ctx, "docker", "network", "ls", "-q", "--no-trunc", "--filter", "name=^"+state.Name+"$")
	if err != nil {
		return "", err
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return "", nil
	}
	if len(ids) != 1 {
		return "", errors.New("eks: ambiguous owned network")
	}
	out, err = k.command(ctx, "docker", "network", "inspect", ids[0])
	if err != nil {
		return "", err
	}
	var networks []struct {
		ID     string `json:"Id"`
		Name   string
		Labels map[string]string
	}
	if err = json.Unmarshal(out, &networks); err != nil {
		return "", err
	}
	if len(networks) != 1 || networks[0].Name != state.Name || networks[0].Labels[ownerLabel] != state.Token || networks[0].Labels[idLabel] != state.ID {
		return "", errors.New("eks: refusing unowned native network")
	}
	return networks[0].ID, nil
}

func (k *K3d) ensureNative(ctx context.Context, state *diskState, dir string, sink AuditSink) (*nativeBridge, error) {
	containers, err := k.ownedContainers(ctx, *state)
	if err != nil {
		return nil, err
	}
	network, err := k.ownedNetwork(ctx, *state)
	if err != nil {
		return nil, err
	}
	volume, err := k.ownedVolume(ctx, *state)
	if err != nil {
		return nil, err
	}
	var server, worker *dockerContainer
	for i := range containers {
		switch containers[i].Name {
		case "/k3d-" + state.Name + "-server-0":
			server = &containers[i]
		case "/k3d-" + state.Name + "-agent-0":
			worker = &containers[i]
		}
	}
	if server != nil && !slices.Contains(server.Config.Cmd, "--disable-agent") {
		return nil, errors.New("eks: retained server includes a workload agent; recreate the cluster with a separate control plane before upgrading")
	}
	if state.Ready && (server == nil || worker == nil || network == "" || volume == "") {
		return nil, errors.New("eks: previously ready Kubernetes was removed externally; refusing empty replacement")
	}
	if network == "" {
		if _, err = k.command(ctx, "docker", "network", "create", "--label", ownerLabel+"="+state.Token, "--label", idLabel+"="+state.ID, state.Name); err != nil {
			return nil, err
		}
	}
	if volume == "" {
		if _, err = k.command(ctx, "docker", "volume", "create", "--label", ownerLabel+"="+state.Token, "--label", idLabel+"="+state.ID, "--label", "k3d.cluster="+state.Name, "k3d-"+state.Name+"-images"); err != nil {
			return nil, err
		}
	}
	bridge, err := k.startBridge(ctx, state, dir, sink)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			bridge.close()
		}
	}()
	if server == nil {
		// k3d's default entrypoint unconditionally cordons/drains its node.
		// Agentless control planes have no Node and must never drain workloads.
		entrypoint := []byte("#!/bin/sh\nset -eu\nfor hook in /bin/k3d-entrypoint-*.sh; do \"$hook\"; done\nexec /bin/k3s \"$@\"\n")
		if err = writePrivate(dir, "control-plane-entrypoint.sh", entrypoint); err != nil {
			return nil, err
		}
		if err = os.Chmod(filepath.Join(dir, "control-plane-entrypoint.sh"), 0700); err != nil {
			return nil, err
		}
		image, _ := PinnedImage(state.InitialVersion)
		args := []string{"cluster", "create", state.Name,
			"--image", image, "--servers", "1", "--agents", "1", "--no-lb", "--no-rollback",
			"--api-port", net.JoinHostPort(state.nativeHost(), fmt.Sprint(state.NativePort)), "--network", state.Name,
			"--runtime-label", ownerLabel + "=" + state.Token + "@all", "--runtime-label", idLabel + "=" + state.ID + "@all",
			"--kubeconfig-update-default=false", "--kubeconfig-switch-context=false",
			"--k3s-arg", "--disable=traefik@server:0",
			"--k3s-arg", "--disable-agent@server:0",
			"--k3s-arg", "--egress-selector-mode=cluster@server:0",
			"--volume", filepath.Join(dir, "control-plane-entrypoint.sh") + ":/bin/k3d-entrypoint.sh:ro@server:0",
			"--volume", filepath.Join(dir, "audit-policy.yaml") + ":/etc/stackd/audit-policy.yaml:ro@server:0",
			"--volume", filepath.Join(dir, "audit-webhook.kubeconfig") + ":/etc/stackd/audit-webhook.kubeconfig:ro@server:0",
			"--wait", "--timeout", "180s"}
		for _, arg := range auditArguments() {
			args = append(args, "--k3s-arg", arg+"@server:0")
		}
		if state.ServiceAccountIssuer != "" {
			for _, arg := range serviceAccountIssuerArguments(state.ServiceAccountIssuer) {
				args = append(args, "--k3s-arg", "--kube-apiserver-arg="+arg+"@server:0")
			}
		}
		if state.WorkerAdvertiseHost != "" {
			// Agents replace their join URL with the advertised API endpoints.
			// Keep supervisor tunnels on the guest-reachable published endpoint.
			args = append(args,
				"--k3s-arg", "--tls-san="+state.WorkerAdvertiseHost+"@server:0",
				"--k3s-arg", "--advertise-address="+state.WorkerAdvertiseHost+"@server:0",
				"--k3s-arg", "--advertise-port="+fmt.Sprint(state.NativePort)+"@server:0")
		}
		workerArgs, err := k.workerArguments(*state, dir)
		if err != nil {
			return nil, err
		}
		args = append(args, workerArgs...)
		if _, err = k.command(ctx, k.config.Binary, args...); err != nil {
			return nil, err
		}
		state.NativeLogging = true
		state.AuditPolicyHash = nativeAuditPolicyHash()
		state.NativeServiceAccountIssuer = state.ServiceAccountIssuer != ""
	} else if !server.State.Running || worker != nil && !worker.State.Running {
		if _, err = k.command(ctx, k.config.Binary, "cluster", "start", state.Name, "--wait", "--timeout", "180s"); err != nil {
			return nil, err
		}
	}
	if err = k.reconcileNativeAuditPolicy(ctx, state, dir); err != nil {
		return nil, err
	}
	if err = k.installServiceAccountIssuer(ctx, state, dir); err != nil {
		return nil, err
	}
	if err = saveState(dir, *state); err != nil {
		return nil, err
	}
	if _, err = k.ownedContainers(ctx, *state); err != nil {
		return nil, err
	}
	kubeconfig, err := k.command(ctx, k.config.Binary, "kubeconfig", "get", state.Name)
	if err != nil {
		return nil, err
	}
	if err = writePrivate(dir, "admin.kubeconfig", kubeconfig); err != nil {
		return nil, err
	}
	ok = true
	return bridge, nil
}

func (k *K3d) ownedVolume(ctx context.Context, state diskState) (string, error) {
	name := "k3d-" + state.Name + "-images"
	out, err := k.command(ctx, "docker", "volume", "ls", "-q", "--filter", "name=^"+name+"$")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", nil
	}
	out, err = k.command(ctx, "docker", "volume", "inspect", name)
	if err != nil {
		return "", err
	}
	var volumes []struct {
		Name   string
		Labels map[string]string
	}
	if err = json.Unmarshal(out, &volumes); err != nil {
		return "", err
	}
	if len(volumes) != 1 || volumes[0].Name != name || volumes[0].Labels[ownerLabel] != state.Token || volumes[0].Labels[idLabel] != state.ID || volumes[0].Labels["k3d.cluster"] != state.Name {
		return "", errors.New("eks: refusing unowned image volume")
	}
	return name, nil
}

type privateKubeconfig struct {
	Clusters []struct {
		Cluster struct {
			Server string
			CA     string `yaml:"certificate-authority-data"`
		}
	}
	Users []struct {
		User struct {
			Certificate string `yaml:"client-certificate-data"`
			Key         string `yaml:"client-key-data"`
		}
	}
}

func openNative(state diskState, dir string) (*nativeCluster, error) {
	data, err := readPrivate(filepath.Join(dir, "admin.kubeconfig"))
	if err != nil {
		return nil, err
	}
	var config privateKubeconfig
	if err = yaml.Unmarshal(data, &config); err != nil {
		return nil, errors.New("eks: invalid private kubeconfig")
	}
	if len(config.Clusters) != 1 || len(config.Users) != 1 {
		return nil, errors.New("eks: private kubeconfig must identify one cluster and client")
	}
	expected := "https://" + net.JoinHostPort(state.nativeHost(), fmt.Sprint(state.NativePort))
	if config.Clusters[0].Cluster.Server != expected {
		return nil, errors.New("eks: private kubeconfig endpoint differs from owned native endpoint")
	}
	ca, err := base64.StdEncoding.DecodeString(config.Clusters[0].Cluster.CA)
	if err != nil {
		return nil, errors.New("eks: invalid native CA")
	}
	cert, err := base64.StdEncoding.DecodeString(config.Users[0].User.Certificate)
	if err != nil {
		return nil, errors.New("eks: invalid native client certificate")
	}
	key, err := base64.StdEncoding.DecodeString(config.Users[0].User.Key)
	if err != nil {
		return nil, errors.New("eks: invalid native client key")
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("eks: invalid native client identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("eks: invalid native trust root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 32}
	return &nativeCluster{state: state, dir: dir, transport: transport, client: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}

func (state diskState) nativeHost() string {
	if state.WorkerAdvertiseHost != "" {
		return state.WorkerAdvertiseHost
	}
	return "127.0.0.1"
}

func (c *nativeCluster) nativeURL() string {
	return "https://" + net.JoinHostPort(c.state.nativeHost(), fmt.Sprint(c.state.NativePort))
}

func (c *nativeCluster) ready(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.nativeURL()+"/readyz", nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("eks: native readyz returned %d", response.StatusCode)
	}
	return nil
}

func (c *nativeCluster) waitReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for {
		err := c.ready(ctx)
		if err == nil {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("eks: readiness: %w: %v", ctx.Err(), err)
		case <-timer.C:
		}
	}
}
