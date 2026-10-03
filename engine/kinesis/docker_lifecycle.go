package kinesis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}

type containerConfig struct {
	docker.ContainerConfig
	Hostname     string
	ExposedPorts map[string]struct{} `json:",omitempty"`
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding `json:",omitempty"`
		Tmpfs        map[string]string
	}
}

type containerInspection struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Labels                     map[string]string
		Entrypoint, Cmd, Env       []string
		User, WorkingDir, Hostname string
	}
	HostConfig struct {
		NetworkMode  string
		Privileged   bool
		Binds        []string
		Mounts       []docker.ContainerMount
		PortBindings map[string][]portBinding
		Tmpfs        map[string]string
	}
	Mounts []struct {
		Type, Name, Destination string
		RW                      bool
	}
	NetworkSettings struct{ Ports map[string][]portBinding }
	State           struct {
		Status, Error                                string
		Running, Paused, Restarting, Dead, OOMKilled bool
		ExitCode                                     int
	}
}

type volumeInspection struct {
	Name, Driver    string
	Labels, Options map[string]string
}

func (d *Docker) inspect(ctx context.Context, name string) (containerInspection, error) {
	var state containerInspection
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	return state, err
}

func (d *Docker) inspectVolume(ctx context.Context, name string) (volumeInspection, error) {
	var state volumeInspection
	err := d.client.JSON(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &state)
	return state, err
}

func (d *Docker) config(spec Specification, role string) containerConfig {
	var config containerConfig
	config.Image = d.imageID
	config.Labels = d.labels(spec, role)
	config.Hostname = "stackd-kinesis"
	config.WorkingDir = "/"
	// Override the image's scratch VOLUMEs with tmpfs: the stream owns exactly
	// one durable volume, and no anonymous volumes survive interrupted setup.
	config.HostConfig.Tmpfs = map[string]string{
		"/etc/kafka/secrets": "rw,nosuid,nodev,size=1m,mode=1777",
		"/mnt/shared/config": "rw,nosuid,nodev,size=16m,mode=1777",
	}
	config.User = "appuser"
	config.Entrypoint = []string{"/bin/bash", "-c"}
	config.Cmd = []string{"exec /etc/kafka/docker/run"}
	config.HostConfig.NetworkMode = "bridge"
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: resourceName(spec, "data"), Target: dockerDataPath, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}}
	if role == "init" {
		config.User = "root"
		config.Entrypoint = []string{"chown"}
		config.Cmd = []string{"appuser:appuser", dockerDataPath}
		config.HostConfig.NetworkMode = "none"
		return config
	}
	// Metadata advertises a stable in-container address. The owned transport
	// resolves it to this container's inspected published endpoint, not the
	// caller's loopback or a broker-supplied arbitrary network destination.
	config.Env = []string{
		"CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk",
		"KAFKA_NODE_ID=1",
		"KAFKA_PROCESS_ROLES=broker,controller",
		"KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093",
		"KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:9092",
		"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT",
		"KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER",
		"KAFKA_CONTROLLER_QUORUM_VOTERS=1@127.0.0.1:9093",
		"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
		"KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1",
		"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1",
		"KAFKA_LOG_DIRS=" + dockerDataPath,
		"KAFKA_LOG_RETENTION_MS=-1",
		"KAFKA_LOG_RETENTION_BYTES=-1",
		"KAFKA_LOG_FLUSH_INTERVAL_MESSAGES=1",
		"KAFKA_LOG_MESSAGE_TIMESTAMP_TYPE=CreateTime",
		"KAFKA_LOG_MESSAGE_TIMESTAMP_BEFORE_MAX_MS=9223372036854775807",
		"KAFKA_LOG_MESSAGE_TIMESTAMP_AFTER_MAX_MS=9223372036854775807",
		"KAFKA_MESSAGE_MAX_BYTES=12582912",
		"KAFKA_REPLICA_FETCH_MAX_BYTES=12582912",
		"KAFKA_AUTO_CREATE_TOPICS_ENABLE=false",
		"KAFKA_HEAP_OPTS=-Xms256m -Xmx512m",
	}
	config.ExposedPorts = map[string]struct{}{"9092/tcp": {}}
	config.HostConfig.PortBindings = map[string][]portBinding{"9092/tcp": {{HostIP: "127.0.0.1", HostPort: ""}}}
	return config
}

func (d *Docker) checkContainer(state containerInspection, spec Specification, role string) error {
	if err := d.checkLabels(state.Config.Labels, spec, role); err != nil {
		return err
	}
	expected := d.config(spec, role)
	if state.Image != d.imageID || !slices.Equal(state.Config.Entrypoint, expected.Entrypoint) || !slices.Equal(state.Config.Cmd, expected.Cmd) || state.Config.User != expected.User || state.Config.WorkingDir != expected.WorkingDir || state.Config.Hostname != expected.Hostname || state.HostConfig.NetworkMode != expected.HostConfig.NetworkMode || state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 {
		return fmt.Errorf("kafka %s container %s has conflicting native configuration", role, state.ID)
	}
	if !maps.Equal(state.HostConfig.Tmpfs, expected.HostConfig.Tmpfs) {
		return fmt.Errorf("kafka container %s has conflicting scratch mounts", state.ID)
	}
	mounts := state.HostConfig.Mounts
	if len(mounts) != 1 || mounts[0].Type != "volume" || mounts[0].Source != resourceName(spec, "data") || mounts[0].Target != dockerDataPath || mounts[0].ReadOnly || !mounts[0].VolumeOptions.NoCopy {
		return fmt.Errorf("kafka %s container %s has conflicting mount configuration", role, state.ID)
	}
	dataMount := false
	for _, mount := range state.Mounts {
		if !mount.RW {
			return fmt.Errorf("kafka container %s has conflicting storage", state.ID)
		}
		switch mount.Destination {
		case dockerDataPath:
			if mount.Type != "volume" || mount.Name != resourceName(spec, "data") {
				return errors.New("kafka durable volume differs from stream owner")
			}
			dataMount = true
		case "/etc/kafka/secrets", "/mnt/shared/config":
			if mount.Type != "tmpfs" {
				return errors.New("kafka scratch mount is not ephemeral")
			}
		default:
			return fmt.Errorf("kafka container %s has unexpected mount %q", state.ID, mount.Destination)
		}
	}
	if !dataMount {
		return errors.New("kafka container is missing its durable volume")
	}
	if role == "broker" {
		expectedEnv := make(map[string]string, len(expected.Env))
		for _, entry := range d.imageEnv {
			key, value, _ := strings.Cut(entry, "=")
			expectedEnv[key] = value
		}
		for _, entry := range expected.Env {
			key, value, _ := strings.Cut(entry, "=")
			expectedEnv[key] = value
		}
		for _, entry := range state.Config.Env {
			key, value, _ := strings.Cut(entry, "=")
			if want, ok := expectedEnv[key]; ok {
				if value != want {
					return fmt.Errorf("kafka container %s has conflicting %s", state.ID, key)
				}
				delete(expectedEnv, key)
			} else {
				return fmt.Errorf("kafka container %s has unexpected configuration %s", state.ID, key)
			}
		}
		if len(expectedEnv) != 0 {
			return errors.New("kafka container lacks required broker configuration")
		}
		bindings := state.HostConfig.PortBindings["9092/tcp"]
		if len(state.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
			return errors.New("kafka container must publish only port 9092 on loopback")
		}
	} else if len(state.HostConfig.PortBindings) != 0 {
		return errors.New("kafka initializer must not publish ports")
	}
	return nil
}

func (d *Docker) checkVolume(volume volumeInspection, spec Specification) error {
	if err := d.checkLabels(volume.Labels, spec, "data"); err != nil {
		return err
	}
	if volume.Name != resourceName(spec, "data") || volume.Driver != "local" || len(volume.Options) != 0 {
		return errors.New("kafka volume has conflicting native storage configuration")
	}
	return nil
}

func (state containerInspection) endpoint(host string) (string, error) {
	ports := state.NetworkSettings.Ports["9092/tcp"]
	if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
		return "", errors.New("kafka container has no exclusive loopback endpoint")
	}
	port, err := strconv.Atoi(ports[0].HostPort)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("kafka container has invalid published port %q", ports[0].HostPort)
	}
	return net.JoinHostPort(host, ports[0].HostPort), nil
}

func (d *Docker) create(ctx context.Context, spec Specification, role string) (containerInspection, error) {
	name := resourceName(spec, role)
	err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), d.config(spec, role), nil)
	if err != nil && !dockerStatus(err, http.StatusConflict) {
		return containerInspection{}, err
	}
	state, err := d.inspect(ctx, name)
	if err != nil {
		return state, err
	}
	return state, d.checkContainer(state, spec, role)
}

func (d *Docker) start(ctx context.Context, state containerInspection) error {
	if state.State.Paused || state.State.Restarting || state.State.Dead {
		return fmt.Errorf("kafka container cannot start in state %+v", state.State)
	}
	if state.State.Running {
		return nil
	}
	err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/start", nil, nil)
	if dockerStatus(err, http.StatusNotModified) {
		return nil
	}
	return err
}

func (d *Docker) prepare(ctx context.Context, spec Specification) (containerInspection, error) {
	state, err := d.inspect(ctx, resourceName(spec, "broker"))
	exists := err == nil
	if err != nil && !dockerStatus(err, http.StatusNotFound) {
		return state, err
	}
	if exists {
		if err := d.checkContainer(state, spec, "broker"); err != nil {
			return state, err
		}
	}
	volumeName := resourceName(spec, "data")
	volume, err := d.inspectVolume(ctx, volumeName)
	if dockerStatus(err, http.StatusNotFound) {
		if exists {
			return state, errors.New("kafka retained container lost its durable volume; refusing an empty replacement")
		}
		err = d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: volumeName, Driver: "local", Labels: d.labels(spec, "data")}, &volume)
	}
	if err != nil {
		return state, err
	}
	if err := d.checkVolume(volume, spec); err != nil {
		return state, err
	}
	if !exists {
		if err := d.initializeVolume(ctx, spec); err != nil {
			return state, err
		}
		state, err = d.create(ctx, spec, "broker")
		if err != nil {
			return state, err
		}
	}
	if err := d.start(ctx, state); err != nil {
		return state, d.failure(ctx, state.ID, err)
	}
	return d.inspect(ctx, state.ID)
}

func (d *Docker) initializeVolume(ctx context.Context, spec Specification) error {
	state, err := d.inspect(ctx, resourceName(spec, "init"))
	if dockerStatus(err, http.StatusNotFound) {
		state, err = d.create(ctx, spec, "init")
	}
	if err != nil {
		return err
	}
	if err := d.checkContainer(state, spec, "init"); err != nil {
		return err
	}
	if err := d.start(ctx, state); err != nil {
		return d.failure(ctx, state.ID, err)
	}
	for {
		state, err = d.inspect(ctx, state.ID)
		if err != nil {
			return err
		}
		if state.State.Status == "exited" {
			if state.State.ExitCode != 0 {
				return d.failure(ctx, state.ID, fmt.Errorf("kafka initializer exited %d", state.State.ExitCode))
			}
			return d.removeContainer(ctx, state.ID)
		}
		if state.State.Dead || state.State.Error != "" {
			return d.failure(ctx, state.ID, errors.New("kafka initializer failed"))
		}
		if err := pause(ctx); err != nil {
			return err
		}
	}
}

func (d *Docker) removeContainer(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return errors.Join(d.client.RemoveContainer(removal, id), ctx.Err())
}

func (d *Docker) failure(ctx context.Context, id string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	state, inspectErr := d.inspect(ctx, id)
	stateJSON, _ := json.Marshal(state.State)
	var logs bytes.Buffer
	response, logErr := d.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs?stdout=true&stderr=true&tail=50", nil, "")
	if logErr == nil {
		logErr = docker.CopyStream(&logs, &logs, io.LimitReader(response.Body, 32<<10))
		response.Body.Close()
	}
	return fmt.Errorf("kafka container %s: %w; state=%s inspect_error=%v logs=%q log_error=%v", id, cause, stateJSON, inspectErr, logs.String(), logErr)
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
