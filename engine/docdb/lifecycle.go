package docdb

import (
	"context"
	"errors"
	"fmt"
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
	ExposedPorts map[string]struct{} `json:",omitempty"`
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding `json:",omitempty"`
	}
}
type containerState struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Labels               map[string]string
		Entrypoint, Cmd, Env []string
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
		Status                                       string
		Running, Paused, Restarting, Dead, OOMKilled bool
		ExitCode                                     int
	}
}
type volumeState struct {
	Name, Driver    string
	Labels, Options map[string]string
}

func (d *Docker) inspect(ctx context.Context, name string) (containerState, error) {
	var state containerState
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	return state, err
}
func (d *Docker) volume(ctx context.Context, id, role string, labels map[string]string, create bool) (volumeState, error) {
	name := d.name(id, role)
	var state volumeState
	err := d.client.JSON(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &state)
	if dockerStatus(err, http.StatusNotFound) && create {
		err = d.client.JSON(ctx, http.MethodPost, "/volumes/create", docker.VolumeConfig{Name: name, Driver: "local", Labels: labels}, &state)
	}
	if err != nil {
		return state, err
	}
	if err := d.checkOwner(state.Labels, id, role); err != nil {
		return state, err
	}
	if state.Name != name || state.Driver != "local" || len(state.Options) != 0 {
		return state, errors.New("conflicting native document database storage configuration")
	}
	return state, nil
}
func (d *Docker) databaseConfig(spec Specification) containerConfig {
	port := portString(spec.Port)
	wire := port + "/tcp"
	var config containerConfig
	config.Image = d.image
	config.Entrypoint = []string{"docker-entrypoint.sh"}
	config.Cmd = []string{"mongod", "--dbpath", "/data/db/database", "--port", port, "--bind_ip_all", "--auth", "--replSet", replicaSet, "--keyFile", "/data/db/security/keyfile", "--tlsMode", "requireTLS", "--tlsCertificateKeyFile", "/data/db/security/server.pem", "--tlsCAFile", "/data/db/security/ca.pem", "--tlsAllowConnectionsWithoutCertificates", "--wiredTigerCacheSizeGB", "0.25", "--oplogSize", "128"}
	config.Env = []string{"MONGO_INITDB_ROOT_USERNAME=" + spec.Username, "MONGO_INITDB_ROOT_PASSWORD_FILE=/run/stackd-docdb-bootstrap"}
	config.Labels = d.labels(spec.ID, "database")
	config.Labels[labelPrefix+"username"] = spec.Username
	config.Labels[labelPrefix+"port"] = port
	config.ExposedPorts = map[string]struct{}{wire: {}}
	config.HostConfig.NetworkMode = "bridge"
	// Both upstream declared mountpoints are explicitly owned. configdb is
	// unused by this non-sharded mongod and cannot allocate an anonymous volume.
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(spec.ID, "data"), Target: "/data/db", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}, {Type: "volume", Source: d.name(spec.ID, "data"), Target: "/data/configdb", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	config.HostConfig.PortBindings = map[string][]portBinding{wire: {{HostIP: "127.0.0.1", HostPort: port}}}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "none"}
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	config.HostConfig.PidsLimit = 512
	return config
}
func (d *Docker) checkDatabase(state containerState, spec Specification) error {
	if err := d.checkOwner(state.Config.Labels, spec.ID, "database"); err != nil {
		return err
	}
	if state.Config.Labels[labelPrefix+"username"] != spec.Username || state.Config.Labels[labelPrefix+"port"] != portString(spec.Port) {
		return errors.New("conflicting native document database identity")
	}
	want := d.databaseConfig(spec)
	if state.Image != want.Image || !slices.Equal(state.Config.Entrypoint, want.Entrypoint) || !slices.Equal(state.Config.Cmd, want.Cmd) || state.HostConfig.Privileged || state.HostConfig.NetworkMode != "bridge" || len(state.HostConfig.Binds) != 0 {
		return errors.New("conflicting native document database process configuration")
	}
	if len(state.Mounts) != len(want.HostConfig.Mounts) {
		return errors.New("conflicting native document database mounts")
	}
	for _, mount := range want.HostConfig.Mounts {
		found := false
		for _, actual := range state.Mounts {
			if actual.Type == mount.Type && actual.Name == mount.Source && actual.Destination == mount.Target && actual.RW != mount.ReadOnly {
				found = true
				break
			}
		}
		if !found {
			return errors.New("conflicting native document database durable mount")
		}
	}
	bindings := state.HostConfig.PortBindings[portString(spec.Port)+"/tcp"]
	if len(state.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != portString(spec.Port) {
		return errors.New("native document database must publish only its exact loopback port")
	}
	return nil
}
func (d *Docker) createDatabase(ctx context.Context, spec Specification) (containerState, error) {
	err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(spec.ID, "database")), d.databaseConfig(spec), nil)
	if err != nil && !dockerStatus(err, http.StatusConflict) {
		return containerState{}, err
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return state, err
	}
	return state, d.checkDatabase(state, spec)
}
func (d *Docker) start(ctx context.Context, state containerState) error {
	if state.State.Paused || state.State.Restarting || state.State.Dead {
		return errors.New("native document database cannot start in current Docker state")
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
func (d *Docker) stop(ctx context.Context, state containerState) error {
	if !state.State.Running {
		return nil
	}
	// Never SIGKILL a process that may be the source of a cold physical backup.
	err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/stop?t=-1", nil, nil)
	if dockerStatus(err, http.StatusNotModified) {
		return nil
	}
	return err
}
func (d *Docker) Ensure(ctx context.Context, spec Specification) (Endpoint, error) {
	if err := validateSpecification(spec); err != nil {
		return Endpoint{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return Endpoint{}, err
	}
	defer d.unlock()
	return d.ensure(ctx, spec)
}
func (d *Docker) ensure(ctx context.Context, spec Specification) (Endpoint, error) {
	// A retained physical-copy worker fences writers after controller loss.
	if err := d.finishHelper(ctx, spec.ID, "backup"); err != nil {
		return Endpoint{}, err
	}
	state, inspectErr := d.inspect(ctx, d.name(spec.ID, "database"))
	if inspectErr != nil && !dockerStatus(inspectErr, http.StatusNotFound) {
		return Endpoint{}, inspectErr
	}
	var reservation net.Listener
	volume, err := d.volume(ctx, spec.ID, "data", nil, false)
	if dockerStatus(err, http.StatusNotFound) && dockerStatus(inspectErr, http.StatusNotFound) {
		reservation, err = d.portRange.Listen(ctx, "127.0.0.1", uint16(spec.Port))
		if err != nil {
			return Endpoint{}, err
		}
		defer reservation.Close()
		spec.Port = int32(reservation.Addr().(*net.TCPAddr).Port)
		labels := d.labels(spec.ID, "data")
		labels[labelPrefix+"username"] = spec.Username
		labels[labelPrefix+"image"] = d.image
		labels[labelPrefix+"port"] = portString(spec.Port)
		volume, err = d.volume(ctx, spec.ID, "data", labels, true)
	}
	if err != nil {
		return Endpoint{}, err
	}
	port, err := strconv.ParseInt(volume.Labels[labelPrefix+"port"], 10, 32)
	if err != nil || port < 1 || port > 65535 || volume.Labels[labelPrefix+"username"] != spec.Username || volume.Labels[labelPrefix+"image"] != d.image || (spec.Port != 0 && spec.Port != int32(port)) {
		return Endpoint{}, errors.New("conflicting retained native document database configuration")
	}
	spec.Port = int32(port)
	if inspectErr == nil {
		err = d.checkDatabase(state, spec)
	} else {
		if reservation == nil {
			reservation, err = d.portRange.Listen(ctx, "127.0.0.1", uint16(spec.Port))
			if err != nil {
				return Endpoint{}, err
			}
			defer reservation.Close()
		}
		state, err = d.createDatabase(ctx, spec)
	}
	if err != nil {
		return Endpoint{}, err
	}
	if volume.Labels[labelPrefix+"snapshot"] != "" {
		if err := d.finishHelper(ctx, spec.ID, "restore"); err != nil {
			return Endpoint{}, err
		}
		complete, err := d.exists(ctx, state.ID, "/data/db/database/WiredTiger")
		if err != nil {
			return Endpoint{}, err
		}
		if !complete {
			return Endpoint{}, errors.New("native restore is incomplete; retry Restore before Ensure")
		}
	}
	if state.State.Status == "created" {
		if err := d.initializeContainer(ctx, state, spec); err != nil {
			return Endpoint{}, err
		}
	}
	ca, err := d.readFile(ctx, state.ID, "/data/db/security/ca.pem")
	if err != nil {
		return Endpoint{}, err
	}
	if reservation != nil {
		if err := reservation.Close(); err != nil {
			return Endpoint{}, err
		}
	}
	if err := d.start(ctx, state); err != nil {
		return Endpoint{}, err
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return Endpoint{}, err
	}
	bindings := state.NetworkSettings.Ports[portString(spec.Port)+"/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != portString(spec.Port) {
		return Endpoint{}, errors.New("native document database has no exact loopback endpoint")
	}
	endpoint := Endpoint{Address: "localhost", Port: spec.Port, ReplicaSet: replicaSet, CA: ca}
	if err := d.ready(ctx, state.ID, endpoint, spec, volume.Labels[labelPrefix+"snapshot"] != ""); err != nil {
		return Endpoint{}, err
	}
	return endpoint, nil
}
func (d *Docker) Stop(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("native document database incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if err := d.finishHelper(ctx, id, "backup"); err != nil {
		return err
	}
	state, err := d.inspect(ctx, d.name(id, "database"))
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := d.checkOwner(state.Config.Labels, id, "database"); err != nil {
		return err
	}
	return d.stop(ctx, state)
}
func (d *Docker) removeVolume(ctx context.Context, id, role string) error {
	volume, err := d.volume(ctx, id, role, nil, false)
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	err = d.client.JSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name), nil, nil)
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}
func (d *Docker) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("native document database incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	for _, role := range []string{"backup", "restore", "database"} {
		state, err := d.inspect(ctx, d.name(id, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := d.checkOwner(state.Config.Labels, id, role); err != nil {
			return err
		}
		if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
			return err
		}
	}
	return d.removeVolume(ctx, id, "data")
}
func (d *Docker) waitRunning(ctx context.Context, id string) error {
	state, err := d.inspect(ctx, id)
	if err != nil {
		return err
	}
	if !state.State.Running {
		return fmt.Errorf("native document database exited before authenticated readiness (exit %d)", state.State.ExitCode)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(150 * time.Millisecond):
		return nil
	}
}
