package docdb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"stackd/compute/docker"
)

// Snapshot takes an offline WiredTiger copy after a clean shutdown, including
// every database, users, indexes and oplog. It is not an online AWS snapshot.
// https://www.mongodb.com/docs/manual/tutorial/backup-with-filesystem-snapshots/
// https://www.mongodb.com/docs/manual/tutorial/restore-replica-set-from-backup/
func (d *Docker) Snapshot(ctx context.Context, spec Specification, snapshot string) (result error) {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if snapshot == "" {
		return errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if err := d.finishHelper(ctx, spec.ID, "backup"); err != nil {
		return err
	}
	volume, err := d.volume(ctx, spec.ID, "data", nil, false)
	if err != nil {
		return err
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return err
	}
	retained, err := strconvPort(volume.Labels[labelPrefix+"port"])
	if err != nil {
		return err
	}
	if spec.Port != 0 && spec.Port != retained {
		return errors.New("snapshot source endpoint mismatch")
	}
	spec.Port = retained
	if err := d.checkDatabase(state, spec); err != nil {
		return err
	}
	labels := d.labels(snapshot, "snapshot")
	labels[labelPrefix+"source"] = spec.ID
	labels[labelPrefix+"username"] = spec.Username
	labels[labelPrefix+"image"] = d.image
	backup, err := d.volume(ctx, snapshot, "snapshot", labels, true)
	if err != nil {
		return err
	}
	for key, want := range labels {
		if backup.Labels[key] != want {
			return errors.New("conflicting native snapshot source or configuration")
		}
	}
	if state.State.Running {
		defer func() {
			recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.startupTimeout)
			defer cancel()
			_, err := d.ensure(recovery, spec)
			result = errors.Join(result, err)
		}()
	}
	if err := d.stop(ctx, state); err != nil {
		return err
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return err
	}
	if state.State.Running || state.State.Status != "exited" || state.State.ExitCode != 0 || state.State.OOMKilled {
		return errors.New("native snapshot requires completed clean MongoDB shutdown")
	}
	helper, err := d.prepareHelper(ctx, spec.ID, "backup", snapshot)
	if err != nil {
		return err
	}
	return d.waitHelper(ctx, helper)
}

// Restore clones a complete cold snapshot into a different immutable incarnation.
// The copied users and password remain authoritative. Replica membership is
// rebound to the destination endpoint before it becomes available.
func (d *Docker) Restore(ctx context.Context, spec Specification, snapshot string) (Endpoint, error) {
	if err := validateSpecification(spec); err != nil {
		return Endpoint{}, err
	}
	if snapshot == "" {
		return Endpoint{}, errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return Endpoint{}, err
	}
	defer d.unlock()
	target, err := d.volume(ctx, spec.ID, "data", nil, false)
	if err == nil {
		if target.Labels[labelPrefix+"snapshot"] != snapshot || target.Labels[labelPrefix+"username"] != spec.Username || target.Labels[labelPrefix+"image"] != d.image {
			return Endpoint{}, errors.New("refusing to restore over a different native database")
		}
		port, err := strconvPort(target.Labels[labelPrefix+"port"])
		if err != nil {
			return Endpoint{}, err
		}
		if spec.Port != 0 && spec.Port != port {
			return Endpoint{}, errors.New("restore endpoint mismatch")
		}
		spec.Port = port
		state, err := d.createDatabase(ctx, spec)
		if err != nil {
			return Endpoint{}, err
		}
		complete, err := d.exists(ctx, state.ID, "/data/db/database/WiredTiger")
		if err != nil {
			return Endpoint{}, err
		}
		if complete {
			startup, cancel := context.WithTimeout(ctx, d.startupTimeout)
			defer cancel()
			return d.ensure(startup, spec)
		}
		if state.State.Running {
			return Endpoint{}, errors.New("refusing to copy over a running native database")
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return Endpoint{}, err
	}
	backup, err := d.volume(ctx, snapshot, "snapshot", nil, false)
	if err != nil {
		return Endpoint{}, err
	}
	if backup.Labels[labelPrefix+"image"] != d.image || backup.Labels[labelPrefix+"username"] != spec.Username || backup.Labels[labelPrefix+"source"] == spec.ID {
		return Endpoint{}, errors.New("snapshot restore requires matching image/user and a distinct database incarnation")
	}
	if spec.Port == 0 {
		spec.Port, err = allocatePort()
		if err != nil {
			return Endpoint{}, err
		}
	}
	labels := d.labels(spec.ID, "data")
	labels[labelPrefix+"snapshot"] = snapshot
	labels[labelPrefix+"username"] = spec.Username
	labels[labelPrefix+"image"] = d.image
	labels[labelPrefix+"port"] = portString(spec.Port)
	target, err = d.volume(ctx, spec.ID, "data", labels, true)
	if err != nil {
		return Endpoint{}, err
	}
	for key, want := range labels {
		if target.Labels[key] != want {
			return Endpoint{}, errors.New("conflicting restore destination")
		}
	}
	helper, err := d.prepareHelper(ctx, spec.ID, "restore", snapshot)
	if err != nil {
		return Endpoint{}, err
	}
	if err := d.waitHelper(ctx, helper); err != nil {
		return Endpoint{}, err
	}
	if err := d.client.RemoveContainer(ctx, helper.ID); err != nil {
		return Endpoint{}, err
	}
	startup, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	return d.ensure(startup, spec)
}
func (d *Docker) helperConfig(id, role, snapshot string) containerConfig {
	var config containerConfig
	config.Image = d.image
	config.Entrypoint = []string{"/bin/sh", "-ec"}
	config.Labels = d.labels(id, role)
	config.Labels[labelPrefix+"snapshot"] = snapshot
	config.HostConfig.NetworkMode = "none"
	config.HostConfig.LogConfig = docker.ContainerLogConfig{Type: "none"}
	config.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	config.HostConfig.PidsLimit = 32
	data := docker.ContainerMount{Type: "volume", Source: d.name(id, "data"), Target: "/data/db", ReadOnly: role == "backup", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}
	backup := docker.ContainerMount{Type: "volume", Source: d.name(snapshot, "snapshot"), Target: "/data/configdb", ReadOnly: role == "restore", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true}}
	config.HostConfig.Mounts = []docker.ContainerMount{data, backup}
	// Atomic directory publication prevents interrupted bytes becoming a backup
	// or restored database. The source mount is always read-only.
	script := `test -f "$1/database/WiredTiger"; if test -d "$2/database"; then exit 0; fi; test -z "$(find "$1/database" -type l -print -quit)"; rm -rf "$2/staging"; cp -a "$1/database" "$2/staging"; sync; mv "$2/staging" "$2/database"; sync`
	if role == "backup" {
		config.Cmd = []string{script, "stackd-docdb-backup", "/data/db", "/data/configdb"}
	} else {
		config.Cmd = []string{script, "stackd-docdb-restore", "/data/configdb", "/data/db"}
	}
	return config
}
func (d *Docker) checkHelper(state containerState, id, role string) error {
	if err := d.checkOwner(state.Config.Labels, id, role); err != nil {
		return err
	}
	snapshot := state.Config.Labels[labelPrefix+"snapshot"]
	if snapshot == "" {
		return errors.New("native copy worker has no snapshot ownership")
	}
	want := d.helperConfig(id, role, snapshot)
	if state.Image != want.Image || !slices.Equal(state.Config.Entrypoint, want.Entrypoint) || !slices.Equal(state.Config.Cmd, want.Cmd) || state.HostConfig.NetworkMode != "none" || state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 || len(state.HostConfig.PortBindings) != 0 || len(state.Mounts) != len(want.HostConfig.Mounts) {
		return errors.New("conflicting native copy worker configuration")
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
			return errors.New("conflicting native copy worker mount")
		}
	}
	return nil
}
func (d *Docker) prepareHelper(ctx context.Context, id, role, snapshot string) (containerState, error) {
	name := d.name(id, role)
	state, err := d.inspect(ctx, name)
	if err == nil {
		if err := d.checkHelper(state, id, role); err != nil {
			return state, err
		}
		if state.Config.Labels[labelPrefix+"snapshot"] != snapshot {
			return state, errors.New("conflicting native copy operation")
		}
		if state.State.Status == "exited" && state.State.ExitCode != 0 {
			if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
				return state, err
			}
			err = &docker.Error{StatusCode: http.StatusNotFound}
		}
	}
	if dockerStatus(err, http.StatusNotFound) {
		err = d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), d.helperConfig(id, role, snapshot), nil)
		if err != nil && !dockerStatus(err, http.StatusConflict) {
			return state, err
		}
		state, err = d.inspect(ctx, name)
	}
	if err != nil {
		return state, err
	}
	if err := d.checkHelper(state, id, role); err != nil {
		return state, err
	}
	if state.Config.Labels[labelPrefix+"snapshot"] != snapshot {
		return state, errors.New("conflicting native copy operation")
	}
	return state, nil
}
func (d *Docker) waitHelper(ctx context.Context, state containerState) error {
	if state.State.Status == "created" {
		if err := d.start(ctx, state); err != nil {
			return err
		}
	}
	var result struct {
		StatusCode int64
		Error      *struct{ Message string }
	}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/wait?condition=not-running", nil, &result); err != nil {
		return err
	}
	if result.StatusCode != 0 || result.Error != nil {
		return fmt.Errorf("native physical copy failed (exit %d); incomplete bytes are not a snapshot", result.StatusCode)
	}
	return nil
}
func (d *Docker) finishHelper(ctx context.Context, id, role string) error {
	state, err := d.inspect(ctx, d.name(id, role))
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := d.checkHelper(state, id, role); err != nil {
		return err
	}
	if err := d.waitHelper(ctx, state); err != nil {
		if role != "backup" {
			return err
		}
		// A terminal failed backup must not permanently prevent its source from
		// reopening. A running copy remains a writer fence after cancellation.
		current, inspectErr := d.inspect(ctx, state.ID)
		if inspectErr != nil || current.State.Status != "exited" {
			return err
		}
	}
	return d.client.RemoveContainer(ctx, state.ID)
}
func (d *Docker) DeleteSnapshot(ctx context.Context, snapshot string) error {
	if snapshot == "" {
		return errors.New("native snapshot incarnation is required")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	volume, err := d.volume(ctx, snapshot, "snapshot", nil, false)
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	source := volume.Labels[labelPrefix+"source"]
	if source == "" {
		return errors.New("native snapshot has no source ownership")
	}
	state, err := d.inspect(ctx, d.name(source, "backup"))
	if err == nil {
		if err := d.checkHelper(state, source, "backup"); err != nil {
			return err
		}
		if state.Config.Labels[labelPrefix+"snapshot"] == snapshot {
			if err := d.finishHelper(ctx, source, "backup"); err != nil {
				return err
			}
		}
	} else if !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	// Docker rejects a volume still mounted by an active restore. Never force
	// deletion of such bytes or search broadly for other namespace resources.
	return d.removeVolume(ctx, snapshot, "snapshot")
}
