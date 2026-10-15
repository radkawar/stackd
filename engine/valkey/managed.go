package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"stackd/compute/docker"
	"stackd/compute/network"
)

func (d *Docker) managedConfig(spec Specification, role string) docker.ContainerConfig {
	c := d.containerConfig(spec)
	c.Labels = d.managedLabels(spec, role)
	c.HostConfig.NetworkMode = "none"
	c.WorkingDir = "/data"
	c.Entrypoint, c.Cmd = []string{"/bin/true"}, nil
	c.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	c.HostConfig.Mounts[0].VolumeOptions.Labels = d.managedLabels(spec, "data")
	if role != "configuration" {
		node, _ := strconv.Atoi(strings.TrimPrefix(role, "node-"))
		n := attachment(spec, node-1)
		c.HostConfig.NetworkMode = n.Bridge
		c.NetworkingConfig = &docker.ContainerNetworkingConfig{EndpointsConfig: map[string]docker.ContainerEndpointConfig{n.Bridge: {MacAddress: n.MAC, IPAMConfig: docker.ContainerEndpointIPAMConfig{IPv4Address: n.Address.String()}}}}
		c.Entrypoint = []string{"/bin/sh", "-ec"}
		// /dev/shm is Docker's fresh private IPC tmpfs on each start. No
		// persistent volume marker can bypass a later packet-policy refresh.
		c.Cmd = []string{fmt.Sprintf("while [ ! -e %s ]; do sleep 0.1; done; exec valkey-server /data/node-%d/valkey.conf", admissionGate, node-1)}
	}
	return c
}
func sameMounts(actual, expected []docker.ContainerMount) bool {
	return slices.EqualFunc(actual, expected, func(a, b docker.ContainerMount) bool {
		return a.Type == b.Type && a.Source == b.Source && a.Target == b.Target && a.ReadOnly == b.ReadOnly && a.VolumeOptions.NoCopy == b.VolumeOptions.NoCopy && maps.Equal(a.VolumeOptions.Labels, b.VolumeOptions.Labels)
	})
}
func (d *Docker) checkManagedContainer(s containerState, spec Specification, role string) error {
	if err := d.checkManagedOwner(s.Config.Labels, spec, role); err != nil {
		return err
	}
	want := d.managedConfig(spec, role)
	h := s.HostConfig
	if s.ID == "" || s.Image != d.image || s.Config.Image != d.image || s.Config.User != want.User || s.Config.WorkingDir != want.WorkingDir || !slices.Equal(s.Config.Entrypoint, want.Entrypoint) || !slices.Equal(s.Config.Cmd, want.Cmd) || h.NetworkMode != want.HostConfig.NetworkMode || h.Privileged || len(h.Binds) != 0 || !sameMounts(h.Mounts, want.HostConfig.Mounts) || !h.ReadonlyRootfs || len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, want.HostConfig.CapDrop) || !slices.Equal(h.SecurityOpt, want.HostConfig.SecurityOpt) || len(h.PortBindings) != 0 || h.PublishAllPorts || len(h.ExtraHosts) != 0 || len(h.DNS) != 0 || len(h.DNSSearch) != 0 || (h.IpcMode != "private" && h.IpcMode != "") || (h.RestartPolicy.Name != "no" && h.RestartPolicy.Name != "") || h.Memory != want.HostConfig.Memory || h.MemorySwap != want.HostConfig.MemorySwap || h.CPUPeriod != want.HostConfig.CPUPeriod || h.CPUQuota != want.HostConfig.CPUQuota || h.PidsLimit != want.HostConfig.PidsLimit {
		return errors.New("managed Valkey process conflicts with fenced native configuration")
	}
	if !d.equalImageEnvironment(s.Config.Env, want.Env, false) {
		return errors.New("managed Valkey native environment conflicts with retained image")
	}
	if len(s.Mounts) != 1 || s.Mounts[0].Type != "volume" || s.Mounts[0].Name != d.name(spec.ID, "data") || s.Mounts[0].Destination != "/data" || !s.Mounts[0].RW {
		return errors.New("managed Valkey process has a foreign native data mount")
	}
	if role == "configuration" {
		if len(s.NetworkSettings.Networks) > 1 {
			return errors.New("managed Valkey configuration helper has unexpected networking")
		}
		for name := range s.NetworkSettings.Networks {
			if name != "none" {
				return errors.New("managed Valkey configuration helper is networked")
			}
		}
		return nil
	}
	node, _ := strconv.Atoi(strings.TrimPrefix(role, "node-"))
	n := attachment(spec, node-1)
	if len(s.NetworkSettings.Networks) != 1 {
		return errors.New("managed Valkey process must have only its exact customer attachment")
	}
	ep, exists := s.NetworkSettings.Networks[n.Bridge]
	// Docker can leave address fields empty while an exact created/stopped
	// endpoint is not yet active. No listener is admitted until re-observed.
	if !exists || ep.IPAMConfig == nil || ep.IPAMConfig.IPv4Address != n.Address.String() || (s.State.Running && (ep.IPAddress != n.Address.String() || ep.Gateway != n.Gateway.String() || !strings.EqualFold(ep.MacAddress, n.MAC))) {
		return errors.New("managed Valkey process attachment conflicts with retained EC2 reservation")
	}
	return nil
}
func (d *Docker) createManagedContainer(ctx context.Context, spec Specification, role string, created *[]string) (containerState, error) {
	name := d.name(spec.ID, role)
	s, err := d.inspectNamed(ctx, name)
	if dockerStatus(err, 404) {
		*created = append(*created, role) // includes a cancelled, accepted create
		config := d.managedConfig(spec, role)
		create := func() error {
			return d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, nil)
		}
		if role == "configuration" {
			err = create()
		} else {
			node, _ := strconv.Atoi(strings.TrimPrefix(role, "node-"))
			err = d.networks.WithBridge(ctx, spec.Networks[node-1].Network, func(bridge network.Bridge) error {
				if bridge.Name != attachment(spec, node-1).Bridge {
					return errors.New("managed Valkey bridge identity changed")
				}
				return create()
			})
		}
		if err != nil {
			return s, err
		}
		s, err = d.inspectNamed(ctx, name)
	}
	if err != nil {
		return s, err
	}
	return s, d.checkManagedContainer(s, spec, role)
}

func managedConfiguration(spec Specification, m manifest, index int) []byte {
	n := m.Nodes[index]
	var cfg strings.Builder
	// Valkey rejects all non-loopback clients when the disabled default ACL
	// user is passwordless, even when a named user authenticates. Managed
	// listeners instead require an explicit IP bind, ACLs and the freshly
	// installed EC2 packet-policy gate. Standalone loopback retains its guard.
	// https://valkey.io/topics/security/#protected-mode
	fmt.Fprintf(&cfg, "bind %s\nprotected-mode no\ndir /data/node-%d\nappendonly yes\nappendfsync always\nsave \"\"\naclfile /data/users.acl\nmasteruser %s\nmasterauth %s\nlogfile \"\"\n", n.Address, index, controllerUser, m.Secret)
	if m.TLSEnabled {
		fmt.Fprintf(&cfg, "port 0\ntls-port %d\ntls-cert-file /data/node-%d/server.crt\ntls-key-file /data/node-%d/server.key\ntls-ca-cert-file /data/ca.crt\ntls-auth-clients no\ntls-replication yes\n", n.Port, index, index)
	} else {
		fmt.Fprintf(&cfg, "port %d\ntls-port 0\n", n.Port)
	}
	if m.ClusterMode {
		fmt.Fprintf(&cfg, "cluster-enabled yes\ncluster-config-file nodes.conf\ncluster-node-timeout 5000\ncluster-port %d\ncluster-announce-ip %s\ncluster-announce-port %d\ncluster-announce-bus-port %d\n", n.BusPort, n.Address, n.Port, n.BusPort)
		if m.TLSEnabled {
			fmt.Fprintf(&cfg, "tls-cluster yes\ncluster-announce-tls-port %d\n", n.Port)
		}
	}
	params := effectiveParameters(spec)
	for _, key := range sortedParameters(params) {
		fmt.Fprintf(&cfg, "%s %q\n", key, params[key])
	}
	return []byte(cfg.String())
}
func (d *Docker) initializeManaged(ctx context.Context, config containerState, spec Specification, m manifest, stopped []bool) error {
	files := []archiveFile{{name: "users.acl", body: []byte(aclFile(spec.Users, m.Secret))}}
	if m.TLSEnabled {
		files = append(files, archiveFile{name: "ca.crt", body: d.certificate})
	}
	for i := range m.Nodes {
		if !stopped[i] {
			continue
		}
		dir := fmt.Sprintf("node-%d/", i)
		files = append(files, archiveFile{name: dir}, archiveFile{name: dir + "valkey.conf", body: managedConfiguration(spec, m, i)})
		if m.TLSEnabled {
			cert, key, err := d.managedCertificate(spec.Networks[i].Network.Address)
			if err != nil {
				return err
			}
			files = append(files, archiveFile{name: dir + "server.crt", body: cert}, archiveFile{name: dir + "server.key", body: key})
		}
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return err
	}
	files = append(files, archiveFile{name: "manifest.json", body: encoded})
	return d.putFiles(ctx, config.ID, files)
}
func (d *Docker) managedPrerequisites(spec Specification) error {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if d.networks == nil || spec.RefreshNetwork == nil {
		return errors.New("managed Valkey requires EC2 observation and the shared native bridge manager")
	}
	if spec.TLSEnabled && (d.tlsConfig == nil || d.ca == nil || d.caKey == nil) {
		return errors.New("managed Valkey TLS requires the configured signing CA and private key")
	}
	return nil
}
func (d *Docker) managedFailure(ctx context.Context, spec Specification, created []string, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	result := errors.Join(cause, d.quarantineManaged(cleanup, spec))
	for _, role := range created {
		s, err := d.inspectNamed(cleanup, d.name(spec.ID, role))
		if dockerStatus(err, 404) {
			err = nil // roll back an admitted bridge even if create never landed
		} else if err == nil {
			err = d.checkManagedContainer(s, spec, role)
			if err == nil {
				err = d.client.RemoveContainer(cleanup, s.ID)
			}
		}
		result = errors.Join(result, err)
		if err != nil || role == "configuration" {
			continue
		}
		node, _ := strconv.Atoi(strings.TrimPrefix(role, "node-"))
		identity := attachment(spec, node-1)
		if d.networks != nil {
			result = errors.Join(result, d.networks.RemovePolicy(cleanup, identity.PolicyTable, identity.PolicyOwner))
			result = errors.Join(result, d.networks.Release(cleanup, identity.NetworkID))
		}
	}
	return result
}
func (d *Docker) ensureManaged(ctx context.Context, spec Specification) (out Deployment, result error) {
	var created []string
	defer func() {
		if result != nil {
			result = d.managedFailure(ctx, spec, created, result)
		}
	}()
	if err := d.managedPrerequisites(spec); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if _, err := d.managedVolume(ctx, spec, "ownership", true); err != nil {
		return out, err
	}
	if _, err := d.managedVolume(ctx, spec, "data", true); err != nil {
		return out, err
	}
	configuration, err := d.createManagedContainer(ctx, spec, "configuration", &created)
	if err != nil {
		return out, err
	}
	m, err := d.readManifest(ctx, configuration, spec)
	missingManifest := dockerStatus(err, 404)
	if dockerStatus(err, 404) {
		m = managedManifest(spec)
	} else if err != nil {
		return out, err
	}
	nodes := make([]containerState, len(spec.Networks))
	stopped := make([]bool, len(nodes))
	for i := range nodes {
		nodes[i], err = d.createManagedContainer(ctx, spec, nodeRole(i), &created)
		if err != nil {
			return out, err
		}
		stopped[i] = !nodes[i].State.Running
		if missingManifest && nodes[i].State.Running {
			return out, errors.New("managed Valkey live node has no retained native manifest")
		}
	}
	if err = d.initializeManaged(ctx, configuration, spec, m, stopped); err != nil {
		return out, err
	}
	for i, s := range nodes {
		if !s.State.Running {
			if err = d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(s.ID)+"/start", nil, nil); err != nil {
				return out, err
			}
		}
		if err = d.configureNodeNetwork(ctx, spec, i, s); err != nil {
			return out, err
		}
	}
	if err = d.checkManagedNative(ctx, m, stopped); err != nil {
		return out, err
	}
	if err = d.checkManagedListeners(ctx, spec, m); err != nil {
		return out, err
	}
	if err = d.applySettings(ctx, configuration, spec, m); err != nil {
		return out, err
	}
	if err = d.topology(ctx, m); err != nil {
		return out, err
	}
	return d.currentDeployment(ctx, m)
}

func (d *Docker) checkManagedListeners(ctx context.Context, spec Specification, m manifest) error {
	for i := range m.Nodes {
		expected := map[string]string{"bind": m.address(i), "port": strconv.Itoa(int(managedPort)), "tls-port": "0", "protected-mode": "no", "aclfile": "/data/users.acl", "dir": fmt.Sprintf("/data/node-%d", i), "appendonly": "yes", "appendfsync": "always", "masteruser": controllerUser, "masterauth": m.Secret, "unixsocket": ""}
		if spec.TLSEnabled {
			expected["port"], expected["tls-port"] = "0", strconv.Itoa(int(managedPort))
			expected["tls-cert-file"], expected["tls-key-file"], expected["tls-ca-cert-file"] = fmt.Sprintf("/data/node-%d/server.crt", i), fmt.Sprintf("/data/node-%d/server.key", i), "/data/ca.crt"
			expected["tls-auth-clients"], expected["tls-replication"] = "no", "yes"
		}
		if spec.ClusterMode {
			expected["cluster-enabled"], expected["cluster-port"], expected["cluster-announce-ip"] = "yes", strconv.Itoa(int(managedBusPort)), m.address(i)
			expected["cluster-announce-port"], expected["cluster-announce-bus-port"] = strconv.Itoa(int(managedPort)), strconv.Itoa(int(managedBusPort))
			if spec.TLSEnabled {
				expected["tls-cluster"], expected["cluster-announce-tls-port"] = "yes", strconv.Itoa(int(managedPort))
			}
		} else {
			expected["cluster-enabled"] = "no"
		}
		c := d.clientFor(m, i)
		args := make([]any, 0, len(expected)+2)
		args = append(args, "CONFIG", "GET")
		for key := range expected {
			args = append(args, key)
		}
		command := redis.NewMapStringStringCmd(ctx, args...)
		err := c.Process(ctx, command)
		actual := command.Val()
		c.Close()
		if err != nil {
			return err
		}
		for key, value := range expected {
			if actual[key] != value {
				return fmt.Errorf("managed Valkey native protected setting %s conflicts with retained intent", key)
			}
		}
	}
	return nil
}

// Startup grace belongs only to nodes started by this reconciliation. A live
// node that loses its current policy/protocol must fail promptly so its owner
// can quarantine it, not keep serving through another full startup window.
func (d *Docker) checkManagedNative(ctx context.Context, m manifest, started []bool) error {
	for i := range m.Nodes {
		if started != nil && started[i] {
			if err := d.waitNativeNode(ctx, m, i); err != nil {
				return err
			}
			continue
		}
		c := d.clientFor(m, i)
		err := c.Ping(ctx).Err()
		if err == nil {
			var info string
			info, err = c.Info(ctx, "server").Result()
			if err == nil && !strings.Contains(info, "valkey_version:"+Version+"\r\n") {
				err = errors.New("native server is not the pinned Valkey version")
			}
		}
		c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func (d *Docker) observeManaged(ctx context.Context, spec Specification) (manifest, error) {
	if err := d.managedPrerequisites(spec); err != nil {
		return manifest{}, err
	}
	if _, err := d.managedVolume(ctx, spec, "ownership", false); err != nil {
		return manifest{}, err
	}
	if _, err := d.managedVolume(ctx, spec, "data", false); err != nil {
		return manifest{}, err
	}
	config, err := d.inspectNamed(ctx, d.name(spec.ID, "configuration"))
	if err != nil {
		return manifest{}, err
	}
	if err = d.checkManagedContainer(config, spec, "configuration"); err != nil {
		return manifest{}, err
	}
	m, err := d.readManifest(ctx, config, spec)
	if err != nil {
		return m, err
	}
	for i := range m.Nodes {
		s, err := d.inspectNamed(ctx, d.name(spec.ID, nodeRole(i)))
		if err != nil {
			return m, err
		}
		if err = d.checkManagedContainer(s, spec, nodeRole(i)); err != nil {
			return m, err
		}
		if !s.State.Running {
			return m, errors.New("managed Valkey node is not running")
		}
		if err = d.configureNodeNetwork(ctx, spec, i, s); err != nil {
			return m, err
		}
	}
	if err = d.checkManagedNative(ctx, m, nil); err != nil {
		return m, err
	}
	return m, d.checkManagedListeners(ctx, spec, m)
}
func (d *Docker) restartManaged(ctx context.Context, spec Specification) (out Deployment, result error) {
	defer func() {
		if result != nil {
			result = d.managedFailure(ctx, spec, nil, result)
		}
	}()
	if err := d.managedPrerequisites(spec); err != nil {
		return out, err
	}
	// Preflight every node before stopping any. Ensure re-observes current EC2
	// under this same runtime lock before reopening each fresh admission gate.
	for i := range spec.Networks {
		s, err := d.inspectNamed(ctx, d.name(spec.ID, nodeRole(i)))
		if err != nil {
			return out, err
		}
		if err = d.checkManagedContainer(s, spec, nodeRole(i)); err != nil {
			return out, err
		}
	}
	if err := d.quarantineManaged(ctx, spec); err != nil {
		return out, err
	}
	return d.ensureManaged(ctx, spec)
}

func (d *Docker) deleteManaged(ctx context.Context, owner nativeDescriptor) error {
	spec := owner.specification()
	if err := owner.validate(); err != nil {
		return err
	}
	if d.networks == nil {
		return errors.New("managed Valkey deletion requires its retained native bridge manager")
	}
	// Preflight all immutable ownership before deleting any exact-owned object.
	var containers []containerState
	roles := []string{"configuration"}
	for i := range spec.Networks {
		roles = append(roles, nodeRole(i))
	}
	for _, role := range roles {
		s, err := d.inspectNamed(ctx, d.name(spec.ID, role))
		if dockerStatus(err, 404) {
			continue
		}
		if err != nil {
			return err
		}
		if err = d.checkManagedContainer(s, spec, role); err != nil {
			return err
		}
		containers = append(containers, s)
	}
	helpers, err := d.retainedManagedHelpers(ctx, spec)
	if err != nil {
		return err
	}
	containers = append(helpers, containers...)
	data, err := d.managedVolume(ctx, spec, "data", false)
	if err != nil && !dockerStatus(err, 404) {
		return err
	}
	ownership, err := d.managedVolume(ctx, spec, "ownership", true)
	if err != nil {
		return err
	}
	for _, s := range containers {
		if err = d.client.RemoveContainer(ctx, s.ID); err != nil {
			return err
		}
	}
	if data.Name != "" {
		if err = d.removeManagedVolume(ctx, data.Name); err != nil {
			return err
		}
	}
	for _, n := range owner.Networks {
		if err = d.networks.RemovePolicy(ctx, n.PolicyTable, n.PolicyOwner); err != nil {
			return err
		}
		if err = d.networks.Release(ctx, n.NetworkID); err != nil {
			return err
		}
	}
	return d.removeManagedVolume(ctx, ownership.Name)
}

func (d *Docker) removeManagedVolume(ctx context.Context, name string) error {
	if err := d.client.JSON(ctx, "DELETE", "/volumes/"+url.PathEscape(name), nil, nil); err != nil && !dockerStatus(err, 404) {
		return err
	}
	var retained volumeState
	err := d.client.JSON(ctx, "GET", "/volumes/"+url.PathEscape(name), nil, &retained)
	if dockerStatus(err, 404) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("managed Valkey native volume retirement was not observed")
}
