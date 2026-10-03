package dynamodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	}
}

type containerInspection struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Labels                     map[string]string
		Entrypoint, Cmd            []string
		User, WorkingDir, Hostname string
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
	NetworkSettings struct{ Ports map[string][]portBinding }
	State           struct {
		Status, Error                                string
		Running, Paused, Restarting, Dead, OOMKilled bool
		ExitCode                                     int
	}
}

type volumeInspection struct {
	Name, Driver string
	Labels       map[string]string
	Options      map[string]string
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
	config.Hostname = "stackd-dynamodb"
	config.WorkingDir = "/home/dynamodblocal"
	config.User = "dynamodblocal"
	config.Entrypoint = []string{"java"}
	config.Cmd = []string{"-jar", "DynamoDBLocal.jar", "-sharedDb", "-dbPath", dockerDataPath, "-disableTelemetry"}
	config.HostConfig.NetworkMode = "bridge"
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: resourceName(spec, "data"), Target: dockerDataPath, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}}
	if role == "init" {
		// Fresh named volumes are root-owned. Only this owned volume is changed;
		// the actual database continues running as the image's unprivileged user.
		config.User = "root"
		config.Entrypoint = []string{"chown"}
		config.Cmd = []string{"dynamodblocal:dynamodblocal", dockerDataPath}
		config.HostConfig.NetworkMode = "none"
	} else {
		config.ExposedPorts = map[string]struct{}{"8000/tcp": {}}
		config.HostConfig.PortBindings = map[string][]portBinding{"8000/tcp": {{HostIP: "127.0.0.1", HostPort: ""}}}
	}
	return config
}

func (d *Docker) checkContainer(state containerInspection, spec Specification, role string) error {
	if err := checkOwner(state.Config.Labels, spec, role); err != nil {
		return err
	}
	if err := d.checkConfiguration(state.Config.Labels); err != nil {
		return err
	}
	expected := d.config(spec, role)
	if state.Image != d.imageID || !slices.Equal(state.Config.Entrypoint, expected.Entrypoint) || !slices.Equal(state.Config.Cmd, expected.Cmd) || state.Config.User != expected.User || state.Config.WorkingDir != expected.WorkingDir || state.Config.Hostname != expected.Hostname || state.HostConfig.NetworkMode != expected.HostConfig.NetworkMode || state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 {
		return fmt.Errorf("DynamoDB %s container %s has conflicting native configuration", role, state.ID)
	}
	if len(state.Mounts) != 1 || state.Mounts[0].Type != "volume" || state.Mounts[0].Name != resourceName(spec, "data") || state.Mounts[0].Destination != dockerDataPath || !state.Mounts[0].RW {
		return fmt.Errorf("DynamoDB %s container %s has conflicting durable volume mounts", role, state.ID)
	}
	if role == "database" {
		bindings := state.HostConfig.PortBindings["8000/tcp"]
		if len(state.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
			return fmt.Errorf("DynamoDB container %s must publish only port 8000 on loopback", state.ID)
		}
	} else if len(state.HostConfig.PortBindings) != 0 {
		return fmt.Errorf("DynamoDB volume initializer %s must not publish ports", state.ID)
	}
	return nil
}

func (state containerInspection) endpoint(host string) (string, error) {
	ports := state.NetworkSettings.Ports["8000/tcp"]
	if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
		return "", fmt.Errorf("DynamoDB container %s has no exclusive loopback endpoint", state.ID)
	}
	port, err := strconv.Atoi(ports[0].HostPort)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("DynamoDB container %s has invalid published port %q", state.ID, ports[0].HostPort)
	}
	return "http://" + net.JoinHostPort(host, ports[0].HostPort), nil
}

func (d *Docker) create(ctx context.Context, spec Specification, role string) (containerInspection, error) {
	name := resourceName(spec, role)
	var result struct {
		ID string `json:"Id"`
	}
	err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), d.config(spec, role), &result)
	// Another controller may have prepared the same stable resource. Adoption
	// still requires inspection of both actual configuration and owner labels.
	if err != nil && !dockerStatus(err, http.StatusConflict) {
		return containerInspection{}, fmt.Errorf("create DynamoDB %s container: %w", role, err)
	}
	state, err := d.inspect(ctx, name)
	if err != nil {
		return state, err
	}
	return state, d.checkContainer(state, spec, role)
}

func (d *Docker) start(ctx context.Context, state containerInspection) error {
	if state.State.Paused || state.State.Restarting || state.State.Dead {
		return fmt.Errorf("DynamoDB container %s cannot start in state %+v", state.ID, state.State)
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
	state, err := d.inspect(ctx, resourceName(spec, "database"))
	exists := err == nil
	if err != nil && !dockerStatus(err, http.StatusNotFound) {
		return state, fmt.Errorf("inspect DynamoDB database: %w", err)
	}
	if exists {
		if err := d.checkContainer(state, spec, "database"); err != nil {
			return state, err
		}
	}
	volumeName := resourceName(spec, "data")
	volume, err := d.inspectVolume(ctx, volumeName)
	if dockerStatus(err, http.StatusNotFound) {
		if exists {
			return state, errors.New("DynamoDB retained container has lost its durable volume; refusing to create an empty replacement")
		}
		err = d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: volumeName, Driver: "local", Labels: d.labels(spec, "data")}, &volume)
	}
	if err != nil {
		return state, fmt.Errorf("prepare DynamoDB volume: %w", err)
	}
	if err := checkOwner(volume.Labels, spec, "data"); err != nil {
		return state, err
	}
	if err := d.checkConfiguration(volume.Labels); err != nil {
		return state, err
	}
	if volume.Name != volumeName || volume.Driver != "local" || len(volume.Options) != 0 {
		return state, errors.New("DynamoDB volume has conflicting native storage configuration")
	}
	if !exists {
		if err := d.initializeVolume(ctx, spec); err != nil {
			return state, err
		}
		state, err = d.create(ctx, spec, "database")
		if err != nil {
			return state, err
		}
	}
	if err := d.start(ctx, state); err != nil {
		return state, d.failure(ctx, state.ID, fmt.Errorf("start DynamoDB Local: %w", err))
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return state, fmt.Errorf("inspect started DynamoDB Local: %w", err)
	}
	return state, nil
}

func (d *Docker) initializeVolume(ctx context.Context, spec Specification) error {
	state, err := d.inspect(ctx, resourceName(spec, "init"))
	if dockerStatus(err, http.StatusNotFound) {
		state, err = d.create(ctx, spec, "init")
	}
	if err != nil {
		return fmt.Errorf("prepare DynamoDB volume initializer: %w", err)
	}
	if err := d.checkContainer(state, spec, "init"); err != nil {
		return err
	}
	if err := d.start(ctx, state); err != nil {
		return d.failure(ctx, state.ID, fmt.Errorf("start DynamoDB volume initializer: %w", err))
	}
	for {
		state, err = d.inspect(ctx, state.ID)
		if err != nil {
			return fmt.Errorf("inspect DynamoDB volume initializer: %w", err)
		}
		if state.State.Status == "exited" {
			if state.State.ExitCode != 0 {
				return d.failure(ctx, state.ID, fmt.Errorf("DynamoDB volume initializer exited %d", state.State.ExitCode))
			}
			return d.removeContainer(ctx, state.ID)
		}
		if state.State.Dead || state.State.Error != "" {
			return d.failure(ctx, state.ID, fmt.Errorf("DynamoDB volume initializer failed: %+v", state.State))
		}
		select {
		case <-ctx.Done():
			return d.failure(ctx, state.ID, fmt.Errorf("waiting for DynamoDB volume permissions: %w", ctx.Err()))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Once DELETE is dispatched, cancellation cannot undo the daemon's removal.
// Keep the lifecycle gate while joining its response, even during shutdown.
// A daemon timeout remains an error; it never permits dependent volume cleanup.
func (d *Docker) removeContainer(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err := d.client.RemoveContainer(removal, id)
	return errors.Join(err, ctx.Err())
}

func (d *Docker) failure(ctx context.Context, id string, cause error) error {
	// Startup cancellation should not discard the diagnostic explaining why a
	// listening JVM could not serve an API. Diagnostics have a separate hard cap.
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
	return fmt.Errorf("DynamoDB Local container %s: %w; state=%s inspect_error=%v logs=%q log_error=%v", id, cause, stateJSON, inspectErr, logs.String(), logErr)
}
