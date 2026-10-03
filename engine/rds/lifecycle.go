package rds

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
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
		Labels          map[string]string
		Entrypoint, Cmd []string
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

func nativeLayout(engine string) (port, mount, subdir string) {
	kind, _ := family(engine)
	if kind == "postgres" {
		return "5432/tcp", "/var/lib/postgresql/data", "/var/lib/postgresql/data/database"
	}
	return "3306/tcp", "/var/lib/mysql", "/var/lib/mysql/database"
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
func (d *Docker) databaseConfig(spec Specification) containerConfig {
	kind, _ := family(spec.Engine)
	port, mount, subdir := nativeLayout(spec.Engine)
	var config containerConfig
	config.Image = d.image(spec.Engine)
	config.Entrypoint = []string{"docker-entrypoint.sh"}
	config.Labels = d.labels(spec.ID, "database")
	config.Labels[labelPrefix+"engine"] = spec.Engine
	config.Labels[labelPrefix+"username"] = spec.Username
	config.Labels[labelPrefix+"database"] = spec.Database
	if kind == "postgres" {
		database := spec.Database
		if database == "" {
			database = "postgres"
		}
		config.Env = []string{"POSTGRES_USER=" + spec.Username, "POSTGRES_DB=" + database, "POSTGRES_PASSWORD_FILE=/run/stackd-rds-password", "PGDATA=" + subdir, "POSTGRES_HOST_AUTH_METHOD=scram-sha-256"}
		config.Cmd = []string{"postgres", "-c", "listen_addresses=*", "-c", "log_statement=none", "-c", "log_min_error_statement=panic"}
	} else {
		config.Env = []string{"MYSQL_DATABASE=" + spec.Database, "MYSQL_ROOT_PASSWORD_FILE=/run/stackd-rds-password", "MYSQL_INITDB_SKIP_TZINFO=1"}
		if spec.Username == "root" {
			config.Env = append(config.Env, "MYSQL_ROOT_HOST=%")
		} else {
			config.Env = append(config.Env, "MYSQL_USER="+spec.Username, "MYSQL_PASSWORD_FILE=/run/stackd-rds-password")
		}
		config.Cmd = []string{"mysqld", "--datadir=" + subdir, "--bind-address=0.0.0.0", "--mysqlx=0", "--general-log=0", "--slow-query-log=0", "--innodb-fast-shutdown=0"}
	}
	names := make([]string, 0, len(spec.Parameters))
	for name := range spec.Parameters {
		if StaticParameter(spec.Engine, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if kind == "postgres" {
			config.Cmd = append(config.Cmd, "-c", name+"="+spec.Parameters[name])
		} else {
			config.Cmd = append(config.Cmd, "--"+name+"="+spec.Parameters[name])
		}
	}
	config.ExposedPorts = map[string]struct{}{port: {}}
	config.HostConfig.NetworkMode = "bridge"
	config.HostConfig.Mounts = []docker.ContainerMount{{Type: "volume", Source: d.name(spec.ID, "data"), Target: mount, VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}}
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "none"}
	config.HostConfig.PidsLimit = 512
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	published := ""
	if spec.Port != 0 {
		published = strconv.Itoa(int(spec.Port))
	}
	config.HostConfig.PortBindings = map[string][]portBinding{port: {{HostIP: "127.0.0.1", HostPort: published}}}
	return config
}
func (d *Docker) checkDatabase(state containerState, spec Specification) error {
	if err := d.checkOwner(state.Config.Labels, spec.ID, "database"); err != nil {
		return err
	}
	if state.Config.Labels[labelPrefix+"engine"] != spec.Engine || state.Config.Labels[labelPrefix+"username"] != spec.Username || state.Config.Labels[labelPrefix+"database"] != spec.Database {
		return errors.New("conflicting native database identity")
	}
	port, mount, _ := nativeLayout(spec.Engine)
	if state.Image != d.image(spec.Engine) || !slices.Equal(state.Config.Entrypoint, []string{"docker-entrypoint.sh"}) || state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 || state.HostConfig.NetworkMode != "bridge" {
		return errors.New("conflicting native database process configuration")
	}
	if len(state.Mounts) != 1 || state.Mounts[0].Type != "volume" || state.Mounts[0].Name != d.name(spec.ID, "data") || state.Mounts[0].Destination != mount || !state.Mounts[0].RW {
		return errors.New("conflicting native database durable mounts")
	}
	bindings := state.HostConfig.PortBindings[port]
	if len(state.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return errors.New("native database must publish only its loopback SQL port")
	}
	return nil
}
func (s containerState) endpoint(host, engine string) (Endpoint, error) {
	port, _, _ := nativeLayout(engine)
	bindings := s.NetworkSettings.Ports[port]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return Endpoint{}, errors.New("native database has no exclusive loopback endpoint")
	}
	value, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil || value < 1 || value > 65535 {
		return Endpoint{}, errors.New("native database has invalid published port")
	}
	return Endpoint{Address: host, Port: int32(value)}, nil
}
func (d *Docker) volume(ctx context.Context, id, role string, labels map[string]string, create bool) (volumeState, error) {
	name := d.name(id, role)
	state, err := d.inspectVolume(ctx, name)
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
		return state, errors.New("conflicting native database storage configuration")
	}
	return state, nil
}
func (d *Docker) initializeContainer(ctx context.Context, state containerState, spec Specification) error {
	// Secrets are private files, not environment or command-line values. Neither
	// native logs nor Docker logs are collected by this runtime.
	var content bytes.Buffer
	archive := tar.NewWriter(&content)
	// Upstream MySQL initialization interpolates its bootstrap password into
	// SQL without quoting. Use a generated transport-safe bootstrap credential,
	// then set the requested credential with correctly quoted native SQL. This
	// also preserves trailing newlines otherwise stripped by *_PASSWORD_FILE.
	bootstrap := rand.Text()
	kind, _ := family(spec.Engine)
	literal := "'" + strings.ReplaceAll(spec.Password, "'", "''") + "'"
	statement := "SET standard_conforming_strings = on;\nALTER ROLE \"" + spec.Username + "\" PASSWORD " + literal + ";\n"
	if kind == "mysql" {
		statement = "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES';\nGRANT ALL PRIVILEGES ON *.* TO '" + spec.Username + "'@'%' WITH GRANT OPTION;\nALTER USER '" + spec.Username + "'@'%' IDENTIFIED BY " + literal + ";\n"
	}
	files := []struct {
		name, body string
		mode       int64
	}{
		{"run/stackd-rds-password", bootstrap, 0400},
		{"docker-entrypoint-initdb.d/stackd-credentials.sql", statement, 0400},
	}
	for _, file := range files {
		if err := archive.WriteHeader(&tar.Header{Name: file.name, Mode: file.mode, Size: int64(len(file.body)), Uid: 999, Gid: 999}); err != nil {
			return err
		}
		if _, err := archive.Write([]byte(file.body)); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	response, err := d.client.Request(ctx, http.MethodPut, "/containers/"+url.PathEscape(state.ID)+"/archive?path=/", &content, "application/x-tar")
	if err != nil {
		return err
	}
	return response.Body.Close()
}
func (d *Docker) createDatabase(ctx context.Context, spec Specification) (containerState, error) {
	var result struct {
		ID string `json:"Id"`
	}
	err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(spec.ID, "database")), d.databaseConfig(spec), &result)
	if err != nil && !dockerStatus(err, http.StatusConflict) {
		return containerState{}, err
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return state, err
	}
	if err := d.checkDatabase(state, spec); err != nil {
		return state, err
	}
	if state.State.Status == "created" {
		err = d.initializeContainer(ctx, state, spec)
	}
	return state, err
}
func (d *Docker) dataDirectoryExists(ctx context.Context, state containerState, spec Specification) (bool, error) {
	_, _, subdir := nativeLayout(spec.Engine)
	response, err := d.client.Request(ctx, http.MethodHead, "/containers/"+url.PathEscape(state.ID)+"/archive?path="+url.QueryEscape(subdir), nil, "")
	if dockerStatus(err, http.StatusNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	response.Body.Close()
	return true, nil
}
func (d *Docker) start(ctx context.Context, state containerState) error {
	if state.State.Paused || state.State.Restarting || state.State.Dead {
		return errors.New("native database cannot start in current Docker state")
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
	// No SIGKILL fallback: copying bytes after an unclean stop must never be
	// advertised as a completed cold backup. Cancellation leaves retained work.
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
	// Join an interrupted cold backup before permitting any writer to resume.
	if err := d.finishBackup(ctx, spec.ID); err != nil {
		return Endpoint{}, err
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	exists := err == nil
	if err != nil && !dockerStatus(err, http.StatusNotFound) {
		return Endpoint{}, err
	}
	if exists {
		if err := d.checkDatabase(state, spec); err != nil {
			return Endpoint{}, err
		}
	}
	labels := d.labels(spec.ID, "data")
	labels[labelPrefix+"engine"] = spec.Engine
	volume, err := d.volume(ctx, spec.ID, "data", labels, !exists)
	if err != nil {
		return Endpoint{}, fmt.Errorf("native database durable volume: %w", err)
	}
	if volume.Labels[labelPrefix+"engine"] != spec.Engine {
		return Endpoint{}, errors.New("native volume engine mismatch")
	}
	if exists {
		config := d.databaseConfig(spec)
		port, _, _ := nativeLayout(spec.Engine)
		bindings := state.HostConfig.PortBindings[port]
		changedPort := spec.Port != 0 && bindings[0].HostPort != strconv.Itoa(int(spec.Port))
		if !slices.Equal(state.Config.Cmd, config.Cmd) || changedPort {
			if spec.Port == 0 {
				endpoint, err := state.endpoint(d.endpointHost, spec.Engine)
				if err == nil {
					spec.Port = endpoint.Port
				}
			}
			if err := d.stop(ctx, state); err != nil {
				return Endpoint{}, err
			}
			if err := d.removeContainer(ctx, state.ID); err != nil {
				return Endpoint{}, err
			}
			exists = false
		}
	}
	if !exists {
		state, err = d.createDatabase(ctx, spec)
		if err != nil {
			return Endpoint{}, err
		}
	} else if state.State.Status == "created" {
		if err := d.initializeContainer(ctx, state, spec); err != nil {
			return Endpoint{}, err
		}
	}
	if volume.Labels[labelPrefix+"snapshot"] != "" && !state.State.Running {
		complete, err := d.dataDirectoryExists(ctx, state, spec)
		if err != nil {
			return Endpoint{}, err
		}
		if !complete {
			return Endpoint{}, errors.New("native restore is incomplete; retry Restore before Ensure")
		}
	}
	if err := d.start(ctx, state); err != nil {
		return Endpoint{}, err
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return Endpoint{}, err
	}
	endpoint, err := state.endpoint(d.endpointHost, spec.Engine)
	if err != nil {
		return Endpoint{}, err
	}
	if err := d.ready(ctx, state.ID, endpoint, spec); err != nil {
		return Endpoint{}, err
	}
	return endpoint, d.applyParameters(ctx, endpoint, spec)
}
func (d *Docker) ready(ctx context.Context, id string, endpoint Endpoint, spec Specification) error {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		db, err := Open(probe, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
		if err == nil {
			var version string
			kind, _ := family(spec.Engine)
			query, expected := "SELECT version()", MySQLVersion
			if kind == "postgres" {
				query, expected = "SHOW server_version", PostgresVersion
			}
			err = db.QueryRowContext(probe, query).Scan(&version)
			db.Close()
			cancel()
			if err != nil {
				return err
			}
			if version != expected && !(kind == "postgres" && len(version) > len(expected) && version[:len(expected)+1] == expected+" ") {
				return fmt.Errorf("native database version %q differs from required %s", version, expected)
			}
			return nil
		}
		cancel()
		state, inspectErr := d.inspect(ctx, id)
		if inspectErr != nil {
			return inspectErr
		}
		if !state.State.Running {
			return fmt.Errorf("native database exited before authenticated readiness (exit %d)", state.State.ExitCode)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("native database authenticated readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
func (d *Docker) Stop(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("native database incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if err := d.finishBackup(ctx, id); err != nil {
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
func (d *Docker) removeContainer(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return errors.Join(d.client.RemoveContainer(removal, id), ctx.Err())
}
func (d *Docker) removeVolume(ctx context.Context, id, role string) error {
	volume, err := d.volume(ctx, id, role, nil, false)
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err = d.client.JSON(removal, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name), nil, nil)
	if dockerStatus(err, http.StatusNotFound) {
		err = nil
	}
	return errors.Join(err, ctx.Err())
}
func (d *Docker) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("native database incarnation is required")
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
		if err := d.removeContainer(ctx, state.ID); err != nil {
			return err
		}
	}
	return d.removeVolume(ctx, id, "data")
}
