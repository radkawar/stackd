package opensearch

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"stackd/compute/docker"
	service "stackd/internal/services/opensearch"
)

const nativePort = "9200/tcp"
const dataPath = "/usr/share/opensearch/data"

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}
type containerConfig struct {
	docker.ContainerConfig
	ExposedPorts map[string]struct{}
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding
	}
}
type containerState struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Labels               map[string]string
		Entrypoint, Cmd, Env []string
		User                 string
	}
	HostConfig struct {
		NetworkMode  string
		Privileged   bool
		Binds        []string
		PortBindings map[string][]portBinding
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	NetworkSettings struct {
		Ports    map[string][]portBinding
		Networks map[string]struct{ NetworkID string }
	}
	State struct {
		Running, Paused, Restarting, Dead bool
		Status                            string
		ExitCode                          int
	}
}
type volumeState struct {
	Name, Driver    string
	Labels, Options map[string]string
}
type networkState struct {
	ID                            string `json:"Id"`
	Name, Driver, Scope           string
	Internal, Attachable, Ingress bool
	Labels, Options               map[string]string
	Containers                    map[string]struct{ Name string }
}

func (d *Docker) inspect(ctx context.Context, name string) (containerState, error) {
	var state containerState
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	return state, err
}
func (d *Docker) inspectVolume(ctx context.Context, name string) (volumeState, error) {
	var state volumeState
	err := d.client.JSON(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &state)
	return state, err
}
func (d *Docker) inspectNetwork(ctx context.Context, name string) (networkState, error) {
	var state networkState
	err := d.client.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, &state)
	return state, err
}
func (d *Docker) checkVolume(state volumeState, id string) error {
	if err := d.checkOwner(state.Labels, id, "data"); err != nil {
		return err
	}
	if state.Name != d.name(id, "data") || state.Driver != "local" || len(state.Options) != 0 {
		return errors.New("conflicting OpenSearch durable volume configuration")
	}
	return nil
}
func (d *Docker) checkNetwork(state networkState, id string) error {
	if err := d.checkOwner(state.Labels, id, "network"); err != nil {
		return err
	}
	if state.Name != d.name(id, "network") || state.Driver != "bridge" || state.Scope != "local" || state.Internal || state.Attachable || state.Ingress || len(state.Options) != 1 || state.Options["com.docker.network.bridge.enable_icc"] != "false" {
		return errors.New("conflicting OpenSearch private network configuration")
	}
	for _, container := range state.Containers {
		if container.Name != d.name(id, "node") {
			return errors.New("foreign container attached to OpenSearch private network")
		}
	}
	return nil
}
func (d *Docker) resources(ctx context.Context, id string, create bool) error {
	volume, err := d.inspectVolume(ctx, d.name(id, "data"))
	if dockerStatus(err, http.StatusNotFound) && create {
		err = d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: d.name(id, "data"), Driver: "local", Labels: d.labels(id, "data")}, &volume)
	}
	if err != nil {
		return err
	}
	if err := d.checkVolume(volume, id); err != nil {
		return err
	}
	network, err := d.inspectNetwork(ctx, d.name(id, "network"))
	if dockerStatus(err, http.StatusNotFound) && create {
		// Docker internal networks do not publish loopback ports. A dedicated
		// bridge with ICC disabled permits host access without sharing peers.
		config := struct {
			Name, Driver    string
			CheckDuplicate  bool
			Labels, Options map[string]string
		}{d.name(id, "network"), "bridge", true, d.labels(id, "network"), map[string]string{"com.docker.network.bridge.enable_icc": "false"}}
		err = d.client.JSON(ctx, http.MethodPost, "/networks/create", config, nil)
		if err == nil {
			network, err = d.inspectNetwork(ctx, d.name(id, "network"))
		}
	}
	if err != nil {
		return err
	}
	return d.checkNetwork(network, id)
}
func (d *Docker) configuration(spec service.NativeSpecification, port string) containerConfig {
	var config containerConfig
	config.Image = d.image
	config.Entrypoint = []string{"./opensearch-docker-entrypoint.sh"}
	config.Cmd = []string{"opensearch", "-Ediscovery.type=single-node", "-Ecluster.name=" + d.name(spec.ID, "cluster"), "-Enode.name=stackd", "-Enetwork.host=0.0.0.0", "-Etransport.host=127.0.0.1", "-Ehttp.port=9200", "-Eindices.query.bool.max_clause_count=" + option(spec.AdvancedOptions, "indices.query.bool.max_clause_count", "1024"), "-Erest.action.multi.allow_explicit_index=" + option(spec.AdvancedOptions, "rest.action.multi.allow_explicit_index", "true")}
	config.Env = []string{"DISABLE_INSTALL_DEMO_CONFIG=true", "DISABLE_SECURITY_PLUGIN=true", "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true", "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m -XX:ActiveProcessorCount=2"}
	config.Labels = d.labels(spec.ID, "node")
	config.ExposedPorts = map[string]struct{}{nativePort: {}}
	config.HostConfig.NetworkMode = d.name(spec.ID, "network")
	config.HostConfig.PortBindings = map[string][]portBinding{nativePort: {{HostIP: "127.0.0.1", HostPort: port}}}
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(spec.ID, "data"), Target: dataPath}}
	config.HostConfig.Memory = 1536 << 20
	config.HostConfig.MemorySwap = config.HostConfig.Memory
	config.HostConfig.CPUPeriod = 100000
	config.HostConfig.CPUQuota = 200000
	config.HostConfig.PidsLimit = 512
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "max-file": "2"}}
	return config
}
func (d *Docker) checkContainer(state containerState, id string) error {
	if err := d.checkOwner(state.Config.Labels, id, "node"); err != nil {
		return err
	}
	if state.Image != d.image || !slices.Equal(state.Config.Entrypoint, []string{"./opensearch-docker-entrypoint.sh"}) || state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 || state.HostConfig.NetworkMode != d.name(id, "network") {
		return errors.New("conflicting OpenSearch process configuration")
	}
	if len(state.Mounts) != 1 || state.Mounts[0].Type != "volume" || state.Mounts[0].Name != d.name(id, "data") || state.Mounts[0].Destination != dataPath || !state.Mounts[0].RW {
		return errors.New("conflicting OpenSearch durable mounts")
	}
	bindings := state.HostConfig.PortBindings[nativePort]
	if len(state.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return errors.New("OpenSearch must publish only its private loopback REST port")
	}
	if len(state.NetworkSettings.Networks) != 1 {
		return errors.New("OpenSearch must attach only to its owned private network")
	}
	if _, ok := state.NetworkSettings.Networks[d.name(id, "network")]; !ok {
		return errors.New("OpenSearch private network is missing")
	}
	return nil
}
func (state containerState) endpoint() (string, error) {
	bindings := state.NetworkSettings.Ports[nativePort]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return "", errors.New("OpenSearch has no exclusive loopback endpoint")
	}
	port, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("OpenSearch has invalid published port")
	}
	return "http://127.0.0.1:" + bindings[0].HostPort, nil
}

// Ensure reconciles only a fresh service-owned incarnation. Configuration changes
// replace the process, not its durable volume. The service fences stale work.
func (d *Docker) Ensure(ctx context.Context, spec service.NativeSpecification) (string, error) {
	if err := validateSpecification(spec); err != nil {
		return "", err
	}
	ctx, leave, err := d.enter(ctx)
	if err != nil {
		return "", err
	}
	defer leave()
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	state, err := d.inspect(ctx, d.name(spec.ID, "node"))
	exists := err == nil
	if err != nil && !dockerStatus(err, http.StatusNotFound) {
		return "", err
	}
	if exists {
		if err := d.checkContainer(state, spec.ID); err != nil {
			return "", err
		}
	}
	if err := d.resources(ctx, spec.ID, !exists); err != nil {
		return "", err
	}
	config := d.configuration(spec, "")
	if exists {
		// Image environment includes upstream defaults as well as our overrides.
		for _, required := range config.Env {
			if !slices.Contains(state.Config.Env, required) {
				return "", errors.New("conflicting OpenSearch native environment")
			}
		}
		if !slices.Equal(state.Config.Cmd, config.Cmd) {
			if endpoint, err := state.endpoint(); err == nil {
				parsed, _ := url.Parse(endpoint)
				config = d.configuration(spec, parsed.Port())
			}
			if state.State.Running {
				err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/stop?t=-1", nil, nil)
				if err != nil && !dockerStatus(err, http.StatusNotModified) {
					return "", err
				}
			}
			if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
				return "", err
			}
			exists = false
		}
	}
	if !exists {
		err = d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(spec.ID, "node")), config, nil)
		if err != nil {
			return "", err
		}
		state, err = d.inspect(ctx, d.name(spec.ID, "node"))
		if err != nil {
			return "", err
		}
		if err := d.checkContainer(state, spec.ID); err != nil {
			return "", err
		}
	}
	if state.State.Paused || state.State.Restarting || state.State.Dead {
		return "", errors.New("OpenSearch cannot start in its current Docker state")
	}
	if !state.State.Running {
		err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/start", nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotModified) {
			return "", err
		}
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return "", err
	}
	endpoint, err := state.endpoint()
	if err != nil {
		return "", err
	}
	if err := d.ready(ctx, state.ID, endpoint, spec.ID); err != nil {
		return "", err
	}
	return endpoint, nil
}

// Delete refuses foreign resources before any mutation and never selects by
// broad labels. A recreated customer domain has a different immutable ID.
func (d *Docker) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("OpenSearch incarnation is required")
	}
	ctx, leave, err := d.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	state, containerErr := d.inspect(ctx, d.name(id, "node"))
	if containerErr == nil {
		if err := d.checkContainer(state, id); err != nil {
			return err
		}
	} else if !dockerStatus(containerErr, http.StatusNotFound) {
		return containerErr
	}
	volume, volumeErr := d.inspectVolume(ctx, d.name(id, "data"))
	if volumeErr == nil {
		if err := d.checkVolume(volume, id); err != nil {
			return err
		}
	} else if !dockerStatus(volumeErr, http.StatusNotFound) {
		return volumeErr
	}
	network, networkErr := d.inspectNetwork(ctx, d.name(id, "network"))
	if networkErr == nil {
		if err := d.checkNetwork(network, id); err != nil {
			return err
		}
	} else if !dockerStatus(networkErr, http.StatusNotFound) {
		return networkErr
	}
	if containerErr == nil {
		if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
			return err
		}
	}
	if volumeErr == nil {
		err = d.client.JSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name), nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotFound) {
			return err
		}
	}
	if networkErr == nil {
		err = d.client.JSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(network.ID), nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotFound) {
			return err
		}
	}
	// Verify absence rather than treating successful delete admission as completion.
	if _, err := d.inspect(ctx, d.name(id, "node")); !dockerStatus(err, http.StatusNotFound) {
		return errors.Join(errors.New("OpenSearch container removal not confirmed"), err)
	}
	if _, err := d.inspectVolume(ctx, d.name(id, "data")); !dockerStatus(err, http.StatusNotFound) {
		return errors.Join(errors.New("OpenSearch volume removal not confirmed"), err)
	}
	if _, err := d.inspectNetwork(ctx, d.name(id, "network")); !dockerStatus(err, http.StatusNotFound) {
		return errors.Join(errors.New("OpenSearch network removal not confirmed"), err)
	}
	return nil
}
