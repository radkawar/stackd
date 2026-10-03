package kafka

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/docker"
	msk "stackd/internal/services/kafka"
)

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}
type containerConfig struct {
	docker.ContainerConfig
	Hostname     string
	ExposedPorts map[string]struct{}
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding
		Tmpfs        map[string]string
	}
}
type containerState struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Labels               map[string]string
		Entrypoint, Cmd, Env []string
		User, Hostname       string
	}
	HostConfig struct {
		NetworkMode  string
		Privileged   bool
		Binds        []string
		Mounts       []docker.ContainerMount
		PortBindings map[string][]portBinding
		Tmpfs        map[string]string
	}
	State struct {
		Running, Paused, Restarting, Dead bool
		ExitCode                          int
		Status, Error                     string
	}
}
type volumeState struct {
	Name, Driver    string
	Labels, Options map[string]string
}
type networkState struct {
	ID              string `json:"Id"`
	Name, Driver    string
	Internal        bool
	Labels, Options map[string]string
}

func (d *Docker) inspect(ctx context.Context, name string) (containerState, error) {
	var state containerState
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	return state, err
}
func (d *Docker) inspectVolume(ctx context.Context, name string) (volumeState, error) {
	var v volumeState
	err := d.client.JSON(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &v)
	return v, err
}
func (d *Docker) checkVolume(v volumeState, spec msk.Specification, role string) error {
	if err := d.checkLabels(v.Labels, spec, role); err != nil {
		return err
	}
	if v.Name != resourceName(spec, role) || v.Driver != "local" || len(v.Options) != 0 {
		return errors.New("MSK volume configuration conflicts with its owner")
	}
	return nil
}
func (d *Docker) ensureVolume(ctx context.Context, spec msk.Specification, role string, allowCreate bool) error {
	v, err := d.inspectVolume(ctx, resourceName(spec, role))
	if dockerStatus(err, http.StatusNotFound) && allowCreate {
		err = d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: resourceName(spec, role), Driver: "local", Labels: d.labels(spec, role)}, &v)
	}
	if err != nil {
		return fmt.Errorf("MSK %s volume unavailable (retained bytes are never replaced): %w", role, err)
	}
	return d.checkVolume(v, spec, role)
}
func (d *Docker) network(ctx context.Context, spec msk.Specification, create bool) (networkState, error) {
	name := resourceName(spec, "network")
	var state networkState
	err := d.client.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, &state)
	if dockerStatus(err, http.StatusNotFound) && create {
		err = d.client.JSON(ctx, http.MethodPost, "/networks/create", struct {
			Name, Driver   string
			CheckDuplicate bool
			Labels         map[string]string
		}{name, "bridge", true, d.labels(spec, "network")}, nil)
		if err == nil {
			err = d.client.JSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, &state)
		}
	}
	if err != nil {
		return state, err
	}
	if err = d.checkLabels(state.Labels, spec, "network"); err != nil {
		return state, err
	}
	if state.Name != name || state.Driver != "bridge" || state.Internal || len(state.Options) != 0 {
		return state, errors.New("MSK network has conflicting configuration")
	}
	return state, nil
}

func (d *Docker) containerConfig(spec msk.Specification, role string, m *material) containerConfig {
	var c containerConfig
	c.Image = d.imageID
	c.Labels = d.labels(spec, role)
	c.Hostname = resourceName(spec, role)
	c.User = "appuser"
	c.HostConfig.Tmpfs = map[string]string{"/etc/kafka/secrets": "rw,nosuid,nodev,size=1m,mode=1777", "/mnt/shared/config": "rw,nosuid,nodev,size=16m,mode=1777"}
	c.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}}
	c.HostConfig.NetworkMode = "none"
	configMount := docker.ContainerMount{Type: "volume", Source: resourceName(spec, "config"), Target: configPath, ReadOnly: true, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}
	if role == "configuration" {
		c.User = "root"
		configMount.ReadOnly = false
		c.HostConfig.Mounts = []docker.ContainerMount{configMount}
		c.HostConfig.Tmpfs[dataPath] = "rw,nosuid,nodev,size=1m"
		c.Entrypoint = []string{"/bin/true"}
		c.Cmd = []string{"configuration"}
		return c
	}
	_, nodeText, _ := strings.Cut(role, "-")
	node, _ := strconv.Atoi(nodeText)
	dataMount := docker.ContainerMount{Type: "volume", Source: resourceName(spec, "data-"+nodeText), Target: dataPath, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}
	if strings.HasPrefix(role, "init-") {
		c.User = "root"
		c.HostConfig.Mounts = []docker.ContainerMount{dataMount}
		c.Entrypoint = []string{"chown"}
		c.Cmd = []string{"appuser:appuser", dataPath}
		return c
	}
	c.HostConfig.NetworkMode = resourceName(spec, "network")
	c.HostConfig.Mounts = []docker.ContainerMount{dataMount, configMount}
	c.Entrypoint = []string{"/bin/bash", "-ec"}
	c.Cmd = []string{`if [ ! -f ` + dataPath + `/meta.properties ]; then /opt/kafka/bin/kafka-storage.sh format --cluster-id "$(cat ` + configPath + `/cluster-id)" --config ` + configPath + `/broker-` + nodeText + `.properties --add-scram "$(cat ` + configPath + `/admin-scram)"; fi; exec /opt/kafka/bin/kafka-server-start.sh ` + configPath + `/broker-` + nodeText + `.properties`}
	c.Env = []string{"KAFKA_HEAP_OPTS=-Xms256m -Xmx512m"}
	c.ExposedPorts = map[string]struct{}{"9092/tcp": {}, "9095/tcp": {}}
	if m != nil {
		p := m.Nodes[node-1]
		c.HostConfig.PortBindings = map[string][]portBinding{"9092/tcp": {{HostIP: d.endpointHost, HostPort: strconv.Itoa(p.Client)}}, "9095/tcp": {{HostIP: d.endpointHost, HostPort: strconv.Itoa(p.Admin)}}}
	}
	return c
}

func (d *Docker) checkContainer(s containerState, spec msk.Specification, role string, m *material) error {
	if err := d.checkLabels(s.Config.Labels, spec, role); err != nil {
		return err
	}
	want := d.containerConfig(spec, role, m)
	sameMounts := slices.EqualFunc(s.HostConfig.Mounts, want.HostConfig.Mounts, func(a, b docker.ContainerMount) bool {
		return a.Type == b.Type && a.Source == b.Source && a.Target == b.Target && a.ReadOnly == b.ReadOnly &&
			a.VolumeOptions.NoCopy == b.VolumeOptions.NoCopy && maps.Equal(a.VolumeOptions.Labels, b.VolumeOptions.Labels)
	})
	if s.Image != d.imageID || s.Config.User != want.User || s.Config.Hostname != want.Hostname || !slices.Equal(s.Config.Entrypoint, want.Entrypoint) || !slices.Equal(s.Config.Cmd, want.Cmd) || s.HostConfig.NetworkMode != want.HostConfig.NetworkMode || s.HostConfig.Privileged || len(s.HostConfig.Binds) != 0 || !sameMounts || !maps.Equal(s.HostConfig.Tmpfs, want.HostConfig.Tmpfs) {
		return fmt.Errorf("MSK container %s has conflicting native configuration", s.ID)
	}
	expectedEnv := make(map[string]string, len(d.imageEnv)+len(want.Env))
	for _, entry := range d.imageEnv {
		key, value, _ := strings.Cut(entry, "=")
		expectedEnv[key] = value
	}
	for _, entry := range want.Env {
		key, value, _ := strings.Cut(entry, "=")
		expectedEnv[key] = value
	}
	actualEnv := make(map[string]string, len(s.Config.Env))
	for _, entry := range s.Config.Env {
		key, value, _ := strings.Cut(entry, "=")
		actualEnv[key] = value
	}
	if !maps.Equal(expectedEnv, actualEnv) {
		return errors.New("MSK container environment conflicts with its native configuration")
	}
	if m != nil || !strings.HasPrefix(role, "broker-") {
		if !maps.EqualFunc(s.HostConfig.PortBindings, want.HostConfig.PortBindings, slices.Equal[[]portBinding]) {
			return errors.New("MSK broker must publish exactly its retained loopback ports")
		}
	}
	return nil
}

func (d *Docker) createContainer(ctx context.Context, spec msk.Specification, role string, m *material) (containerState, error) {
	name := resourceName(spec, role)
	s, err := d.inspect(ctx, name)
	if dockerStatus(err, http.StatusNotFound) {
		err = d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), d.containerConfig(spec, role, m), nil)
		if err == nil || dockerStatus(err, http.StatusConflict) {
			s, err = d.inspect(ctx, name)
		}
	}
	if err != nil {
		return s, err
	}
	return s, d.checkContainer(s, spec, role, m)
}
func (d *Docker) start(ctx context.Context, s containerState) error {
	if s.State.Running {
		return nil
	}
	if s.State.Paused || s.State.Restarting || s.State.Dead {
		return fmt.Errorf("MSK broker cannot start from %s", s.State.Status)
	}
	err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(s.ID)+"/start", nil, nil)
	if dockerStatus(err, http.StatusNotModified) {
		return nil
	}
	return err
}
func (d *Docker) initializeData(ctx context.Context, spec msk.Specification, node int) error {
	role := "init-" + strconv.Itoa(node)
	s, err := d.createContainer(ctx, spec, role, nil)
	if err != nil {
		return err
	}
	if err = d.start(ctx, s); err != nil {
		return err
	}
	var result struct {
		StatusCode int
		Error      *struct{ Message string }
	}
	if err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(s.ID)+"/wait?condition=not-running", nil, &result); err != nil {
		return err
	}
	if result.StatusCode != 0 || result.Error != nil {
		return fmt.Errorf("MSK data initializer failed with status %d", result.StatusCode)
	}
	return d.client.RemoveContainer(ctx, s.ID)
}

func (d *Docker) readMaterial(ctx context.Context, id string) (*material, error) {
	response, err := d.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(configPath+"/material.json"), nil, "")
	if dockerStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	tr := tar.NewReader(io.LimitReader(response.Body, 1<<20))
	if _, err = tr.Next(); err != nil {
		return nil, err
	}
	var m material
	if err = json.NewDecoder(tr).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}
func (d *Docker) writeConfiguration(ctx context.Context, id string, spec msk.Specification, m *material, properties map[string]string) error {
	encoded, err := json.Marshal(m)
	if err != nil {
		return err
	}
	files := map[string][]byte{"material.json": encoded, "cluster-id": []byte(m.ClusterID), "ca.pem": m.CAPEM, "admin-scram": []byte("SCRAM-SHA-512=[name=" + adminUser + ",iterations=8192,password=" + m.AdminPassword + "]")}
	for node := range m.Nodes {
		files[fmt.Sprintf("broker-%d.properties", node+1)] = d.brokerProperties(spec, m, node, properties)
	}
	var data bytes.Buffer
	tw := tar.NewWriter(&data)
	for name, content := range files {
		if err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content)), Uid: 1000, Gid: 1000}); err != nil {
			return err
		}
		if _, err = tw.Write(content); err != nil {
			return err
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	response, err := d.client.Request(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(configPath), &data, "application/x-tar")
	if err != nil {
		return err
	}
	return response.Body.Close()
}
